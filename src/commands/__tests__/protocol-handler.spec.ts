// Copyright (c) 2026 dotandev
// SPDX-License-Identifier: MIT OR Apache-2.0

import { Command } from 'commander';
import { registerProtocolCommands } from '../protocol-handler';
import { ProtocolRegistrar } from '../../protocol/register';

jest.mock('../../protocol/register');

describe('Protocol commands CLI', () => {
    let program: Command;

    beforeEach(() => {
        program = new Command();
        registerProtocolCommands(program);
        jest.clearAllMocks();
    });

    describe('protocol:verify', () => {
        it('prints all verification checks and success message', async () => {
            (ProtocolRegistrar as unknown as jest.Mock).mockImplementation(() => ({
                verifyRegistration: jest.fn().mockResolvedValue({
                    platform: 'win32',
                    protocol: 'erst',
                    registered: true,
                    checks: [
                        { name: 'registry key', success: true, details: 'Registry key exists' },
                        { name: 'shell open command', success: true, details: 'Command matches' },
                    ],
                }),
            } as unknown as ProtocolRegistrar));

            const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();

            await program.parseAsync(['node', 'test', 'protocol:verify']);

            expect(consoleLogSpy).toHaveBeenCalledWith('Protocol verification for erst:// on win32');
            expect(consoleLogSpy).toHaveBeenCalledWith('[OK] registry key: Registry key exists');
            expect(consoleLogSpy).toHaveBeenCalledWith('[OK] shell open command: Command matches');
            expect(consoleLogSpy).toHaveBeenCalledWith('[OK] Protocol registration verification succeeded');

            consoleLogSpy.mockRestore();
        });

        it('exits with an error when verification fails', async () => {
            (ProtocolRegistrar as unknown as jest.Mock).mockImplementation(() => ({
                verifyRegistration: jest.fn().mockResolvedValue({
                    platform: 'darwin',
                    protocol: 'erst',
                    registered: false,
                    checks: [
                        { name: 'plist file', success: false, details: 'LaunchAgent plist does not exist' },
                    ],
                }),
            } as unknown as ProtocolRegistrar));

            const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
            const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
            const processExitSpy = jest.spyOn(process, 'exit').mockImplementation((() => undefined) as any);

            await program.parseAsync(['node', 'test', 'protocol:verify']);

            expect(consoleLogSpy).toHaveBeenCalledWith('[FAIL] plist file: LaunchAgent plist does not exist');
            expect(consoleErrorSpy).toHaveBeenCalledWith('[FAIL] Protocol registration verification failed');
            expect(processExitSpy).toHaveBeenCalledWith(1);

            consoleLogSpy.mockRestore();
            consoleErrorSpy.mockRestore();
            processExitSpy.mockRestore();
        });
    });
});
