import unittest

from balloon import (
    _balloon,
    balloon,
    balloon_hash,
    balloon_m,
    balloon_m_hash,
    verify,
    verify_m,
)


class TestBalloon(unittest.TestCase):
    def test_invalid_params(self):
        test_vectors = [
            {"args": ("", "", -1, 0, 0), "param": "space_cost"},
            {"args": ("", "", 0, -1, 0), "param": "time_cost"},
            {"args": ("", "", 0, 0, -1), "param": "delta"},
        ]

        for test_vector in test_vectors:
            with self.assertRaises(ValueError) as context:
                _balloon(*test_vector["args"])
            self.assertEqual(
                str(context.exception),
                "'%s' must be a non-negative integer." % test_vector["param"],
            )

    def test_vectors(self):
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

        for test_vector in test_vectors:
            test_params = list(test_vector.values())
            self.assertEqual(balloon(*test_params[:4]).hex(), test_vector["output"])
            self.assertEqual(
                balloon_hash(test_vector["password"], test_vector["salt"]),
                balloon(test_vector["password"], test_vector["salt"], 16, 20, 4).hex(),
            )
            self.assertTrue(verify(test_vector["output"], *test_params[:4]))
            self.assertFalse(verify("0" * 64, *test_params[:4]))


class TestBalloonM(unittest.TestCase):
    def test_invalid_params(self):
        with self.assertRaises(ValueError) as context:
            balloon_m("", "", 0, 0, -1, 0)
        self.assertEqual(
            str(context.exception), "'parallel_cost' must be a positive integer."
        )

    def test_vectors(self):
        test_vectors = [
            {
                "password": "hunter42",
                "salt": "examplesalt",
                "s_cost": 1024,
                "t_cost": 3,
                "p_cost": 4,
                "output": "1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f",
            },
            {
                "password": "",
                "salt": "salt",
                "s_cost": 3,
                "t_cost": 3,
                "p_cost": 2,
                "output": "f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23",
            },
            {
                "password": "password",
                "salt": "",
                "s_cost": 3,
                "t_cost": 3,
                "p_cost": 3,
                "output": "bcad257eff3d1090b50276514857e60db5d0ec484129013ef3c88f7d36e438d6",
            },
            {
                "password": "password",
                "salt": "",
                "s_cost": 3,
                "t_cost": 3,
                "p_cost": 1,
                "output": "498344ee9d31baf82cc93ebb3874fe0b76e164302c1cefa1b63a90a69afb9b4d",
            },
            {
                "password": "\000",
                "salt": "\000",
                "s_cost": 3,
                "t_cost": 3,
                "p_cost": 4,
                "output": "8a665611e40710ba1fd78c181549c750f17c12e423c11930ce997f04c7153e0c",
            },
            {
                "password": "\000",
                "salt": "\000",
                "s_cost": 3,
                "t_cost": 3,
                "p_cost": 1,
                "output": "d9e33c683451b21fb3720afbd78bf12518c1d4401fa39f054b052a145c968bb1",
            },
            {
                "password": "password",
                "salt": "salt",
                "s_cost": 1,
                "t_cost": 1,
                "p_cost": 16,
                "output": "a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915",
            },
            {
                "password": "password",
                "salt": "salt",
                "s_cost": 1,
                "t_cost": 1,
                "p_cost": 1,
                "output": "97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d",
            },
        ]

        for test_vector in test_vectors:
            test_params = list(test_vector.values())
            self.assertEqual(balloon_m(*test_params[:5]).hex(), test_vector["output"])
            self.assertEqual(
                balloon_m_hash(test_vector["password"], test_vector["salt"]),
                balloon_m(
                    test_vector["password"], test_vector["salt"], 16, 20, 4, 4
                ).hex(),
            )
            self.assertTrue(verify_m(test_vector["output"], *test_params[:5]))
            self.assertFalse(verify_m("0" * 64, *test_params[:5]))


if __name__ == "__main__":
    unittest.main()
