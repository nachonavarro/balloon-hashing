import unittest

from balloon import balloon, balloon_hash, balloon_m, balloon_m_hash


class TestBalloon(unittest.TestCase):

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
            self.assertEqual(balloon(test_vector["password"], test_vector["salt"], test_vector["s_cost"], test_vector["t_cost"]).hex(), test_vector["output"])
        

class TestBalloonHash(unittest.TestCase):

    def test_vectors(self):
        test_vectors = [
            {
                "password": "hunter42",
                "salt": "examplesalt",
                "output": "345d33a7525fe7d9333755558935bb8e1d40c12c2d54a76570216dacf9cefab7",
            },
            {
                "password": "",
                "salt": "salt",
                "output": "02a172a57253cb9bd6cd411e4692b2f45f6a2e78b045181fbb89b45e58fffc9f",
            },
            {
                "password": "password",
                "salt": "",
                "output": "07c1a77859de05af68908a058edca4f6a2714d267359c30c2e13997c3c444d4e",
            },
            {
                "password": "\0",
                "salt": "\0",
                "output": "082a125a9e022cf6d4e59a39a8f6b8a4951e752cf9b517cd237ac68fc8921806",
            },
            {
                "password": "password",
                "salt": "salt",
                "output": "0991cbcc01078e50e8e8fbdf8aba03f6bc326f26cd0dd8dfbc269544688ddf7d",
            },
        ]

        for test_vector in test_vectors:
            self.assertEqual(balloon_hash(test_vector["password"], test_vector["salt"]), test_vector["output"])

class TestBalloonM(unittest.TestCase):

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
            self.assertEqual(balloon_m(test_vector["password"], test_vector["salt"], test_vector["s_cost"], test_vector["t_cost"], test_vector["p_cost"]).hex(), test_vector["output"])

class TestBalloonMHash(unittest.TestCase):

    def test_vectors(self):
        test_vectors = [
            {
                "password": "hunter42",
                "salt": "examplesalt",
                "output": "07223b99c38300c3eed167512cce91b00f1dde7a1eb37a5d250ce63477741508",
            },
            {
                "password": "",
                "salt": "salt",
                "output": "05b9ea72b0c80f6b6dd3c191fd06aa0b290fa5ce724c8cf5284835724ad09283",
            },
            {
                "password": "password",
                "salt": "",
                "output": "bf90306b24d7c90dcbc16e9fb21570bbfdf3df2c9465b5a33e2ee2a9b57c0a0a",
            },
            {
                "password": "\0",
                "salt": "\0",
                "output": "eef924e768ac2e03c84a76fd37aaa71372f575bbb53674e49f8ce4864e987fe2",
            },
            {
                "password": "password",
                "salt": "salt",
                "output": "57b737dc8e95e6fb44141a7db9fb34abea63efd8ee8890205bd37be9ebf73271",
            },
        ]

        for test_vector in test_vectors:
            self.assertEqual(balloon_m_hash(test_vector["password"], test_vector["salt"]), test_vector["output"])

if __name__ == '__main__':
    unittest.main()
