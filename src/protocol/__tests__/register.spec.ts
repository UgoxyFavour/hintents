// Copyright (c) 2026 dotandev
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ProtocolRegistrar } from '../register';

describe('ProtocolRegistrar verification', () => {
    const cliPath = '/opt/erst/bin/erst';
    const homedir = '/Users/tester';

    it('verifies required Windows registry keys and command', async () => {
        const exec = jest.fn(async (command: string) => {
            if (command === 'reg query "HKEY_CURRENT_USER\\Software\\Classes\\erst"') {
                return {
                    stdout: 'HKEY_CURRENT_USER\\Software\\Classes\\erst',
                    stderr: '',
                };
            }

            if (command === 'reg query "HKEY_CURRENT_USER\\Software\\Classes\\erst" /v "URL Protocol"') {
                return {
                    stdout: 'URL Protocol    REG_SZ',
                    stderr: '',
                };
            }

            if (command === 'reg query "HKEY_CURRENT_USER\\Software\\Classes\\erst\\shell\\open\\command" /ve') {
                return {
                    stdout: `    (Default)    REG_SZ    "${cliPath}" protocol-handler "%1"`,
                    stderr: '',
                };
            }

            throw new Error(`Unexpected command: ${command}`);
        });

        const registrar = new ProtocolRegistrar({
            cliPath,
            exec,
            platform: () => 'win32',
        });

        const result = await registrar.verifyRegistration();

        expect(result.registered).toBe(true);
        expect(result.checks).toEqual([
            expect.objectContaining({ name: 'registry key', success: true }),
            expect.objectContaining({ name: 'URL Protocol value', success: true }),
            expect.objectContaining({ name: 'shell open command', success: true }),
        ]);
    });

    it('fails macOS verification when the plist is missing', async () => {
        const registrar = new ProtocolRegistrar({
            cliPath,
            fileSystem: {
                access: jest.fn().mockRejectedValue(new Error('missing')),
                mkdir: jest.fn(),
                readFile: jest.fn(),
                unlink: jest.fn(),
                writeFile: jest.fn(),
            },
            homedir: () => homedir,
            platform: () => 'darwin',
        });

        const result = await registrar.verifyRegistration();

        expect(result.registered).toBe(false);
        expect(result.checks).toEqual([
            expect.objectContaining({
                name: 'plist file',
                success: false,
                details: expect.stringContaining('does not exist'),
            }),
        ]);
    });

    it('verifies macOS plist contents when the plist exists', async () => {
        const plistContents = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleURLSchemes</key>
    <array>
        <string>erst</string>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>${cliPath}</string>
        <string>protocol-handler</string>
    </array>
</dict>
</plist>`;

        const registrar = new ProtocolRegistrar({
            cliPath,
            fileSystem: {
                access: jest.fn().mockResolvedValue(undefined),
                mkdir: jest.fn(),
                readFile: jest.fn().mockResolvedValue(plistContents),
                unlink: jest.fn(),
                writeFile: jest.fn(),
            },
            homedir: () => homedir,
            platform: () => 'darwin',
        });

        const result = await registrar.verifyRegistration();

        expect(result.registered).toBe(true);
        expect(result.checks).toEqual([
            expect.objectContaining({ name: 'plist file', success: true }),
            expect.objectContaining({ name: 'plist protocol scheme', success: true }),
            expect.objectContaining({ name: 'plist executable path', success: true }),
            expect.objectContaining({ name: 'plist handler command', success: true }),
        ]);
    });

    it('verifies Linux desktop entry and xdg-mime registration', async () => {
        const desktopContents = `[Desktop Entry]
Exec=${cliPath} protocol-handler %u
MimeType=x-scheme-handler/erst;`;

        const exec = jest.fn(async (command: string) => {
            if (command === 'xdg-mime query default x-scheme-handler/erst') {
                return { stdout: 'erst-protocol.desktop\n', stderr: '' };
            }

            throw new Error(`Unexpected command: ${command}`);
        });

        const registrar = new ProtocolRegistrar({
            cliPath,
            exec,
            fileSystem: {
                access: jest.fn().mockResolvedValue(undefined),
                mkdir: jest.fn(),
                readFile: jest.fn().mockResolvedValue(desktopContents),
                unlink: jest.fn(),
                writeFile: jest.fn(),
            },
            homedir: () => '/home/tester',
            platform: () => 'linux',
        });

        const result = await registrar.verifyRegistration();

        expect(result.registered).toBe(true);
        expect(result.checks).toEqual([
            expect.objectContaining({ name: 'desktop file', success: true }),
            expect.objectContaining({ name: 'desktop Exec command', success: true }),
            expect.objectContaining({ name: 'desktop MIME type', success: true }),
            expect.objectContaining({ name: 'xdg-mime registration', success: true }),
        ]);
    });
});
