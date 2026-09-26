# Process Hollowing Detector

A simple, portable Windows application with a clean dark console-style UI that scans currently running Windows processes for indicators associated with possible process hollowing.

## Build Requirements

1. Node.js (v18+)
2. .NET Framework (csc.exe should be available at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`)

## Building from source

1. Run `npm install` to install dependencies.
2. Run `npm run build` to compile the native Windows scanner and build the portable Node.js executable.
3. The portable `.exe` will be located in the `dist/` directory.

## Features

- **Process Scan**: Scans all active processes for executable memory anomalies (unbacked executable memory or modified image sections).
- **Modules Scan**: Deeper scan of module memory mappings.
- **Reporting**: Automatically outputs results to `Downloads\report.txt`.

## Disclaimer

This is a defensive forensic and security research tool. It does not perform any offensive actions.
