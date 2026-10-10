"""Moves-only MCP timing probe. Frames stay in memory; stdout is metadata only."""
import argparse
import base64
import io
import json
import statistics
import subprocess
import time

from PIL import Image, ImageChops


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keyctl", required=True)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--format", choices=["png", "jpeg"])
    parser.add_argument("--image-benchmark", action="store_true")
    parser.add_argument("--images-only", action="store_true")
    parser.add_argument("--batch", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.samples <= 100:
        parser.error("samples must be 1..100")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [args.keyctl, "mcp", "--device", "00000000-0000-4000-8000-000000000099"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, creationflags=flags,
    )
    request_id = 0

    def rpc(method, params):
        nonlocal request_id
        request_id += 1
        process.stdin.write(json.dumps(dict(jsonrpc="2.0", id=request_id,
                                           method=method, params=params)) + "\n")
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        if "error" in response:
            raise RuntimeError(response["error"])
        return response["result"]

    def call(name, arguments):
        result = rpc("tools/call", dict(name=name, arguments=arguments))
        if result.get("isError"):
            # Never replay a failed or uncertain command.
            raise RuntimeError(result.get("structuredContent"))
        return result

    def picture(result):
        block = next(c for c in result["content"] if c["type"] == "image")
        return Image.open(io.BytesIO(base64.b64decode(block["data"]))).convert("RGB")

    try:
        rpc("initialize", dict(protocolVersion="2025-11-25", capabilities={},
                               clientInfo=dict(name="moves-only-probe", version="1")))
        process.stdin.write(json.dumps(dict(jsonrpc="2.0", method="notifications/initialized")) + "\n")
        process.stdin.flush()
        status = call("status", {})["structuredContent"]["device"]
        if not args.images_only and (status["link"] != "authenticated" or status["armed"] or status.get("firmware", {}).get("board_compatibility_id") != 1):
            raise RuntimeError("requires authenticated, disarmed Waveshare")
        print(json.dumps(dict(route=status.get("via"), link_path=status.get("link_path"), endpoint=status.get("firmware", {}).get("endpoint"))), flush=True)
        shot = call("screenshot", {})
        print(json.dumps(dict(capture={key: shot["structuredContent"].get(key) for key in ("width", "height", "native_width", "native_height", "frame_age_ms")})), flush=True)
        previous = picture(shot)
        if args.calibrate and not args.images_only:
            result = call("calibrate", {})["structuredContent"]
            print(json.dumps(dict(calibration=result)), flush=True)
            previous = picture(call("screenshot", {}))
        if args.image_benchmark or args.images_only:
            for format_name in ("png", "jpeg"):
                rows = []
                for _ in range(10):
                    start = time.perf_counter()
                    result = call("screenshot", dict(format=format_name))
                    elapsed = (time.perf_counter()-start)*1000
                    metadata = result["structuredContent"]
                    rows.append(dict(roundtrip_ms=elapsed, encode_ms=metadata["image_encode_ms"], bytes=metadata["image_bytes"]))
                print(json.dumps(dict(format=format_name, image_benchmark={key: statistics.median(r[key] for r in rows) for key in rows[0]})), flush=True)
        if args.images_only:
            return
        if args.batch:
            if args.samples > 32:
                raise RuntimeError("batch is bounded to 32 actions")
            actions = [dict(tool="move", arguments=dict(x=int(previous.width*(0.25 if index%2==0 else 0.75)),
                                                       y=int(previous.height*(0.45 if index%2==0 else 0.65)),
                                                       uncalibrated=True)) for index in range(args.samples)]
            start = time.perf_counter()
            arguments = dict(actions=actions)
            if args.format:
                arguments["format"] = args.format
            result = call("batch", arguments)
            print(json.dumps(dict(batch_ms=round((time.perf_counter()-start)*1000,1),
                                  completed=result["structuredContent"]["completed"],
                                  actions=[{key: r.get(key) for key in ("latency_ms", "settled", "cursor_px")} for r in result["structuredContent"]["actions"]])), flush=True)
            return
        timings = []
        for index in range(args.samples):
            x = int(previous.width * (0.25 if index % 2 == 0 else 0.75))
            y = int(previous.height * (0.45 if index % 2 == 0 else 0.65))
            start = time.perf_counter()
            arguments = dict(x=x, y=y, uncalibrated=True)
            if args.format:
                arguments["format"] = args.format
            result = call("move", arguments)
            action_ms = (time.perf_counter() - start) * 1000
            metadata = result["structuredContent"]
            shot_start = time.perf_counter()
            if not any(c["type"] == "image" for c in result["content"]):
                result = call("screenshot", {})
            image = picture(result)
            roi = (max(0, x - 8), max(0, y - 8), min(image.width, x + 40), min(image.height, y + 48))
            delta = ImageChops.difference(previous.crop(roi), image.crop(roi))
            changed = sum(max(pixel) >= 35 for pixel in delta.get_flattened_data())
            row = dict(sample=index + 1, action_ms=round(action_ms, 1),
                       latency_ms=metadata.get("latency_ms"), settled=metadata.get("settled"),
                       cursor_px=metadata.get("cursor_px"),
                       settle_method=metadata.get("settle_method"),
                       submission_ms=metadata.get("command", metadata).get("submission_ms"),
                       target_changed_pixels=changed,
                       screenshot_decode_ms=round((time.perf_counter() - shot_start) * 1000, 1))
            timings.append(row)
            print(json.dumps(row), flush=True)
            previous = image
        print(json.dumps({key: dict(median=statistics.median(r[key] for r in timings),
                                    minimum=min(r[key] for r in timings),
                                    maximum=max(r[key] for r in timings))
                          for key in ("action_ms", "latency_ms", "screenshot_decode_ms")}), flush=True)
        status = call("status", {})["structuredContent"]["device"]
        print(json.dumps(dict(final_route=status.get("via"), link_path=status.get("link_path"))), flush=True)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    main()
