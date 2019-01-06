import unittest
from mandate import camel_to_snake, snake_to_camel


class testUtil(unittest.TestCase):
    def test_camel_to_snake(self):
        assert(camel_to_snake('hello') == 'hello')
        assert(camel_to_snake('helloWorld') == 'hello_world')
        assert(camel_to_snake('HelloWorld') == 'hello_world')
        assert(camel_to_snake('hello9World') == 'hello9_world')
        assert(camel_to_snake('ThisIsCool') == 'this_is_cool')

    def test_snake_to_camel(self):
        assert(snake_to_camel('hello') == 'Hello')
        assert(snake_to_camel('hello_world') == 'HelloWorld')
        assert(snake_to_camel('some_snake_case') == 'SomeSnakeCase')
