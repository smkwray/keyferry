import unittest
from scripts.check_process_spawns import production_code


class SpawnPolicyScannerTests(unittest.TestCase):
    def test_production_after_test_module_is_still_scanned(self):
        source = '#[cfg(test)] mod tests { fn test() { Command::new("fake"); } }\nfn live() { Command::new("live"); }'
        code = production_code(source)
        self.assertEqual(code.count("Command::new("), 1)

    def test_literals_comments_and_continued_strings_do_not_hide_production(self):
        source = 'const TEXT: &str = "continued\\\nstring"; // Command::new("comment")\nfn live() { Command::new("live"); }'
        self.assertEqual(production_code(source).count("Command::new("), 1)

    def test_raw_strings_and_brace_chars_cannot_confuse_test_boundary(self):
        source = '''#[cfg(test)] mod tests { fn test() { let text = r#"{ \" }"#; let brace = '}'; Command::new("test"); } }
fn live() { Command::new("live"); }'''
        self.assertEqual(production_code(source).count("Command::new("), 1)
