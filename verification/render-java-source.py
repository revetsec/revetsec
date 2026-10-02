#!/usr/bin/env python3
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Render an authored Java fixture for a JDK-only compiler without changing its canonical source."""
import argparse
import importlib.util
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    if arguments.source.resolve() == arguments.output.resolve():
        parser.error("Use a separate temporary output path")
    helper = Path(__file__).resolve().parent / "packaged-consumer/verify-packaged-consumer.py"
    specification = importlib.util.spec_from_file_location("consumer_source_render", helper)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    canonical = arguments.source.read_text(encoding="utf-8")
    arguments.output.write_text(module.annotation_free_source(canonical), encoding="utf-8")


if __name__ == "__main__":
    main()
