from balloon import balloon
import unittest

test_vectors = [
    {
        "password": "hunter42",
        "salt": "examplesalt",
        "s_cost": 1024,
        "t_cost": 3,
        "output": "716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb",
    },
    {
        "password": "",
        "salt": "salt",
        "s_cost": 3,
        "t_cost": 3,
        "output": "5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378",
    },
    {
        "password": "password",
        "salt": "",
        "s_cost": 3,
        "t_cost": 3,
        "output": "20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc",
    },
    {
        "password": "\0",
        "salt": "\0",
        "s_cost": 3,
        "t_cost": 3,
        "output": "4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4",
    },
    {
        "password": "password",
        "salt": "salt",
        "s_cost": 1,
        "t_cost": 1,
        "output": "eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545",
    },
]

class TestVectors(unittest.TestCase):

    def test_vectors(self):
        for test_vector in test_vectors:
            self.assertEqual(balloon(test_vector["password"], test_vector["salt"], test_vector["s_cost"], test_vector["t_cost"]).hex(), test_vector["output"])

if __name__ == '__main__':
    unittest.main()
