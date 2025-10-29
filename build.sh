#!/bin/bash

# Compile server
gcc -o server Server.c

# Compile client
gcc -o client Client.c

echo "Build complete"
