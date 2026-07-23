FROM python:3.12.10-alpine3.21@sha256:9c51ecce261773a684c8345b2d4673700055c513b4d54bc0719337d3e4ee552e

RUN addgroup -S octobench && adduser -S -G octobench -u 10001 octobench
WORKDIR /opt/octobench

# The fixture library is stdlib-only.  Copy only its package boundary rather
# than the application runtime or any campaign/controller state.
COPY core/__init__.py /opt/octobench/core/__init__.py
COPY core/version.py /opt/octobench/core/version.py
COPY core/benchmarks/__init__.py /opt/octobench/core/benchmarks/__init__.py
COPY core/benchmarks/v3 /opt/octobench/core/benchmarks/v3
COPY benchmarks/competitors/labs/discovery-lab-v3/app.py /opt/octobench/app.py

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=15s --start-period=5s --retries=8 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/__octobench_health', timeout=1).read()"]
CMD ["python", "/opt/octobench/app.py"]
