# Test fixtures

`user_keys_response.json`, `encrypted_item_response.json` and `item_response.json` are
copied unchanged from the test suite of the official Python client
[passwork-python](https://github.com/passwork-europe/passwork-python)
(`tests/mock_data/`), MIT License, Copyright (c) 2025 Passwork. The full license text is
in [LICENSE.passwork-python](LICENSE.passwork-python).

They contain synthetic test keys and test data published with that project, not anyone's
secrets. The master key that unlocks `user_keys_response.json` is the `mock_master_key`
fixture of that project's `tests/conftest.py` and is hardcoded in `../vectors.rs`.
