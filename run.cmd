@echo off
if not exist hash\ (
    poetry install
)
poetry run