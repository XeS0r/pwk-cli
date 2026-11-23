# Third-party notices

## passwork-python

pwk is an independent implementation of the Passwork 7 API in Rust. The official Python
client [passwork-python](https://github.com/passwork-europe/passwork-python) served as
the reference for the protocol and the client-side encryption (see
[docs/protocol.md](docs/protocol.md)), and parts of pwk follow its logic closely. Its
test data is copied unchanged into `crates/crypto/tests/fixtures/` and
`crates/api/tests/fixtures/`.

passwork-python is distributed under the following license:

```text
MIT License

Copyright (c) 2025 Passwork

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
