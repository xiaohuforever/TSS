#!/bin/bash

echo "Building EdDSA demo..."
go build -o eddsa_demo eddsa_demo.go

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Running EdDSA demo..."
./eddsa_demo

echo "Cleaning up..."
rm -f eddsa_demo