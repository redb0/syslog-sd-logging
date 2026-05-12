"""Test data for tests."""

import pytz


class SomeClass:  # noqa: D101
    def __init__(self) -> None:
        self.a = 'a'
        self.b = 1

    def __str__(self) -> str:  # noqa: D105
        return 'MyClass Object'


address = ('127.0.0.1', 514)
timezone = pytz.timezone('Antarctica/Vostok')
message = 'This is an interesting message'

sd1 = {'my_sd_id1@32473': {'my_key1': 'my_value1'}}
sd2 = {'my_sd_id2@32473': {'my_key2': 'my_value2'}}
sd_multi_id = {}
sd_multi_id.update(sd1)
sd_multi_id.update(sd2)
sd_multi_param = {'my_sd_id1@32473': {'my_key1': 'my_value1', 'my_key2': 'my_value2'}}

sd1_no_pen = {'my_sd_id1': {'my_key1': 'my_value1'}}
sd2_no_pen = {'my_sd_id2': {'my_key2': 'my_value2'}}
sd_multi_id_no_pen = {}
sd_multi_id_no_pen.update(sd1_no_pen)
sd_multi_id_no_pen.update(sd2_no_pen)

sd1_param_none_value = {'my_sd_id1@32473': {'my_key1': None}}
sd1_param_object_value = {'my_sd_id1@32473': {'my_key1': SomeClass()}}
sd1_param_none_key = {'my_sd_id1@32473': {None: 'my_value1'}}
