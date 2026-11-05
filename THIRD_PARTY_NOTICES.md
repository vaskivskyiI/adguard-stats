# Third-party notices

AdGuard Stats is MIT-licensed (see [LICENSE](LICENSE)). The container image built from this
repository also contains the following third-party software, under their own licenses:

| Component | Use | License |
|---|---|---|
| [Apache ECharts](https://echarts.apache.org) 5.5.1 | Charts; downloaded into the image at build time | Apache-2.0 |
| [FastAPI](https://github.com/fastapi/fastapi) | HTTP API | MIT |
| [Uvicorn](https://github.com/encode/uvicorn) | ASGI server | BSD-3-Clause |
| [tldextract](https://github.com/john-kurkowski/tldextract) | Registrable-domain parsing | BSD-3-Clause |
| [Public Suffix List](https://publicsuffix.org) (bundled with tldextract) | Domain suffix data | MPL-2.0 |
| [tzdata](https://github.com/python/tzdata) | Time zone data | Apache-2.0 |
| [Python](https://www.python.org) base image | Runtime | PSF-2.0 |

The service names and groups loaded at runtime come from your own AdGuard Home instance
(AdGuard Home is GPL-3.0; this project only talks to its HTTP API and does not include its code).

AdGuard is a trademark of AdGuard Software Ltd. This project is not affiliated with or endorsed by AdGuard.
