// Copyright (c) 2026 dotandev
// SPDX-License-Identifier: MIT OR Apache-2.0

import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs/promises';
import { constants as fsConstants } from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

type ExecResult = {
    stdout: string;
    stderr: string;
};

type ExecFunction = (command: string) => Promise<ExecResult>;

type FileSystemLike = Pick<typeof fs, 'access' | 'mkdir' | 'readFile' | 'unlink' | 'writeFile'>;

type PlatformName = NodeJS.Platform;

export interface ProtocolVerificationCheck {
    name: string;
    success: boolean;
    details: string;
}

export interface ProtocolVerificationResult {
    platform: PlatformName;
    protocol: string;
    registered: boolean;
    checks: ProtocolVerificationCheck[];
}

interface ProtocolRegistrarOptions {
    cliPath?: string;
    exec?: ExecFunction;
    fileSystem?: FileSystemLike;
    homedir?: () => string;
    platform?: () => PlatformName;
export interface ProtocolDiagnostics {
    registered: boolean;
    cliPath: string | null;
    pathExists: boolean;
    isExecutable: boolean;
}

/**
 * ProtocolRegistrar handles the registration and unregistration of the
 * custom URI protocol handler (erst://) across different operating systems.
 */
export class ProtocolRegistrar {
    private readonly protocol = 'erst';
    private readonly cliPath: string;
    private readonly exec: ExecFunction;
    private readonly fileSystem: FileSystemLike;
    private readonly getHomedir: () => string;
    private readonly getPlatform: () => PlatformName;

    constructor(options: ProtocolRegistrarOptions = {}) {
        // Get the absolute path to the ERST CLI executable
        // In production, this would be the actual binary path
        this.cliPath = options.cliPath ?? process.execPath;
        this.exec = options.exec ?? execAsync;
        this.fileSystem = options.fileSystem ?? fs;
        this.getHomedir = options.homedir ?? os.homedir;
        this.getPlatform = options.platform ?? os.platform;
    }

    /**
     * Register the erst:// protocol handler for the current OS
     */
    async register(): Promise<void> {
        const platform = this.getPlatform();

        try {
            switch (platform) {
                case 'win32':
                    await this.registerWindows();
                    break;
                case 'darwin':
                    await this.registerMacOS();
                    break;
                case 'linux':
                    await this.registerLinux();
                    break;
                default:
                    throw new Error(`Unsupported platform: ${platform}`);
            }

            console.log(` Protocol handler registered for ${this.protocol}://`);
        } catch (error) {
            console.error('Failed to register protocol handler:', error);
            throw error;
        }
    }

    /**
     * Windows: Register via Registry
     */
    private async registerWindows(): Promise<void> {
        const regPath = `HKEY_CURRENT_USER\\Software\\Classes\\${this.protocol}`;

        const commands = [
            `reg add "${regPath}" /ve /d "URL:ERST Protocol" /f`,
            `reg add "${regPath}" /v "URL Protocol" /d "" /f`,
            `reg add "${regPath}\\shell\\open\\command" /ve /d "\\"${this.cliPath}\\" protocol-handler \\"%1\\"" /f`,
        ];

        for (const cmd of commands) {
            await this.exec(cmd);
        }
    }

    /**
     * macOS: Register via Info.plist
     */
    private async registerMacOS(): Promise<void> {
        // Create a LaunchAgent plist file
        const plistPath = path.join(
            this.getHomedir(),
            'Library',
            'LaunchAgents',
            `com.erst.protocol.plist`,
        );

        const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.erst.protocol</string>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLName</key>
            <string>ERST Protocol</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>${this.protocol}</string>
            </array>
        </dict>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>${this.cliPath}</string>
        <string>protocol-handler</string>
    </array>
    <key>StandardInPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/tmp/erst-protocol.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/erst-protocol-error.log</string>
</dict>
</plist>`;

        await this.fileSystem.mkdir(path.dirname(plistPath), { recursive: true });
        await this.fileSystem.writeFile(plistPath, plistContent, 'utf8');
        await this.exec(`launchctl load ${plistPath}`);
    }

    /**
     * Linux: Register via .desktop file
     */
    private async registerLinux(): Promise<void> {
        const desktopPath = path.join(
            this.getHomedir(),
            '.local',
            'share',
            'applications',
            'erst-protocol.desktop',
        );

        const desktopContent = `[Desktop Entry]
Version=1.0
Type=Application
Name=ERST Protocol Handler
Exec=${this.cliPath} protocol-handler %u
MimeType=x-scheme-handler/${this.protocol};
NoDisplay=true
Terminal=false`;

        // Ensure directory exists
        await this.fileSystem.mkdir(path.dirname(desktopPath), { recursive: true });
        await this.fileSystem.writeFile(desktopPath, desktopContent, 'utf8');

        // Register MIME type
        await this.exec(`xdg-mime default erst-protocol.desktop x-scheme-handler/${this.protocol}`);
        await this.exec('update-desktop-database ~/.local/share/applications/');
    }

    /**
     * Unregister protocol handler
     */
    async unregister(): Promise<void> {
        const platform = this.getPlatform();

        try {
            switch (platform) {
                case 'win32':
                    await this.exec(`reg delete "HKEY_CURRENT_USER\\Software\\Classes\\${this.protocol}" /f`);
                    break;
                case 'darwin':
                    const plistPath = this.getMacOSPlistPath();
                    await this.exec(`launchctl unload ${plistPath}`);
                    await this.fileSystem.unlink(plistPath);
                    break;
                case 'linux':
                    const desktopPath = this.getLinuxDesktopPath();
                    await this.fileSystem.unlink(desktopPath);
                    break;
            }

            console.log(' Protocol handler unregistered');
        } catch (error) {
            console.error('Failed to unregister protocol handler:', error);
        }
    }

    /**
     * Check if protocol is already registered
     */
    async isRegistered(): Promise<boolean> {
        const verification = await this.verifyRegistration();
        return verification.registered;
    }

    async verifyRegistration(): Promise<ProtocolVerificationResult> {
        const platform = this.getPlatform();

        switch (platform) {
            case 'win32':
                return this.verifyWindowsRegistration();
            case 'darwin':
                return this.verifyMacOSRegistration();
            case 'linux':
                return this.verifyLinuxRegistration();
            default:
                return {
                    platform,
                    protocol: this.protocol,
                    registered: false,
                    checks: [{
                        name: 'platform',
                        success: false,
                        details: `Unsupported platform: ${platform}`,
                    }],
                };
        }
    }

    private getWindowsRegistryPath(): string {
        return `HKEY_CURRENT_USER\\Software\\Classes\\${this.protocol}`;
    }

    private getMacOSPlistPath(): string {
        return path.join(this.getHomedir(), 'Library', 'LaunchAgents', 'com.erst.protocol.plist');
    }

    private getLinuxDesktopPath(): string {
        return path.join(this.getHomedir(), '.local', 'share', 'applications', 'erst-protocol.desktop');
    }

    private async verifyWindowsRegistration(): Promise<ProtocolVerificationResult> {
        const regPath = this.getWindowsRegistryPath();
        const expectedCommand = `"${this.cliPath}" protocol-handler "%1"`;

        const checks = await Promise.all([
            this.createExecCheck(
                'registry key',
                `reg query "${regPath}"`,
                (stdout) => stdout.includes(regPath),
                `Registry key exists at ${regPath}`,
                `Registry key ${regPath} was not found`,
            ),
            this.createExecCheck(
                'URL Protocol value',
                `reg query "${regPath}" /v "URL Protocol"`,
                (stdout) => stdout.includes('URL Protocol'),
                'URL Protocol value exists',
                'URL Protocol value is missing',
            ),
            this.createExecCheck(
                'shell open command',
                `reg query "${regPath}\\shell\\open\\command" /ve`,
                (stdout) => stdout.includes(expectedCommand),
                `Open command matches expected handler: ${expectedCommand}`,
                `Open command does not match expected handler: ${expectedCommand}`,
            ),
        ]);

        return this.buildVerificationResult('win32', checks);
    }

    private async verifyMacOSRegistration(): Promise<ProtocolVerificationResult> {
        const plistPath = this.getMacOSPlistPath();
        const checks: ProtocolVerificationCheck[] = [];

        const exists = await this.createAccessCheck(
            'plist file',
            plistPath,
            `LaunchAgent plist exists at ${plistPath}`,
            `LaunchAgent plist does not exist at ${plistPath}`,
        );
        checks.push(exists);

        if (exists.success) {
            const plistContents = await this.fileSystem.readFile(plistPath, 'utf8');

            checks.push(this.createContentCheck(
                'plist protocol scheme',
                plistContents.includes(`<string>${this.protocol}</string>`),
                `Plist contains the ${this.protocol} scheme`,
                `Plist does not contain the ${this.protocol} scheme`,
            ));
            checks.push(this.createContentCheck(
                'plist executable path',
                plistContents.includes(`<string>${this.cliPath}</string>`),
                `Plist points to CLI executable ${this.cliPath}`,
                `Plist does not point to CLI executable ${this.cliPath}`,
            ));
            checks.push(this.createContentCheck(
                'plist handler command',
                plistContents.includes('<string>protocol-handler</string>'),
                'Plist launches the protocol-handler command',
                'Plist does not launch the protocol-handler command',
            ));
        }

        return this.buildVerificationResult('darwin', checks);
    }

    private async verifyLinuxRegistration(): Promise<ProtocolVerificationResult> {
        const desktopPath = this.getLinuxDesktopPath();
        const checks: ProtocolVerificationCheck[] = [];

        const exists = await this.createAccessCheck(
            'desktop file',
            desktopPath,
            `Desktop entry exists at ${desktopPath}`,
            `Desktop entry does not exist at ${desktopPath}`,
        );
        checks.push(exists);

        if (exists.success) {
            const desktopContents = await this.fileSystem.readFile(desktopPath, 'utf8');

            checks.push(this.createContentCheck(
                'desktop Exec command',
                desktopContents.includes(`Exec=${this.cliPath} protocol-handler %u`),
                `Desktop entry executes ${this.cliPath} protocol-handler %u`,
                `Desktop entry does not execute ${this.cliPath} protocol-handler %u`,
            ));
            checks.push(this.createContentCheck(
                'desktop MIME type',
                desktopContents.includes(`MimeType=x-scheme-handler/${this.protocol};`),
                `Desktop entry advertises x-scheme-handler/${this.protocol}`,
                `Desktop entry does not advertise x-scheme-handler/${this.protocol}`,
            ));
            checks.push(await this.createExecCheck(
                'xdg-mime registration',
                `xdg-mime query default x-scheme-handler/${this.protocol}`,
                (stdout) => stdout.trim() === 'erst-protocol.desktop',
                'xdg-mime resolves to erst-protocol.desktop',
                'xdg-mime does not resolve to erst-protocol.desktop',
            ));
        }

        return this.buildVerificationResult('linux', checks);
    }

    private async createAccessCheck(
        name: string,
        targetPath: string,
        successDetails: string,
        failureDetails: string,
    ): Promise<ProtocolVerificationCheck> {
        try {
            await this.fileSystem.access(targetPath);
            return { name, success: true, details: successDetails };
        } catch {
            return { name, success: false, details: failureDetails };
        }
    }

    private createContentCheck(
        name: string,
        success: boolean,
        successDetails: string,
        failureDetails: string,
    ): ProtocolVerificationCheck {
        return {
            name,
            success,
            details: success ? successDetails : failureDetails,
        };
    }

    private async createExecCheck(
        name: string,
        command: string,
        validator: (stdout: string) => boolean,
        successDetails: string,
        failureDetails: string,
    ): Promise<ProtocolVerificationCheck> {
        try {
            const { stdout } = await this.exec(command);
            const success = validator(stdout);

            return {
                name,
                success,
                details: success ? successDetails : failureDetails,
            };
        } catch (error) {
            const details = error instanceof Error ? error.message : String(error);
            return {
                name,
                success: false,
                details: `${failureDetails}. Command failed: ${details}`,
            };
        }
    }

    private buildVerificationResult(
        platform: PlatformName,
        checks: ProtocolVerificationCheck[],
    ): ProtocolVerificationResult {
        return {
            platform,
            protocol: this.protocol,
            registered: checks.length > 0 && checks.every((check) => check.success),
            checks,
        };
    async getRegisteredPath(): Promise<string | null> {
        const platform = os.platform();

        try {
            switch (platform) {
                case 'win32': {
                    const { stdout } = await execAsync(
                        `reg query "HKEY_CURRENT_USER\\Software\\Classes\\${this.protocol}\\shell\\open\\command" /ve`
                    );
                    const match = stdout.match(/"([^"]+)"\s+protocol-handler/);
                    return match ? match[1] : null;
                }
                case 'darwin': {
                    const plistPath = path.join(
                        os.homedir(), 'Library', 'LaunchAgents', 'com.erst.protocol.plist'
                    );
                    const content = await fs.readFile(plistPath, 'utf8');
                    const match = content.match(/<key>ProgramArguments<\/key>\s*<array>\s*<string>([^<]+)<\/string>/);
                    return match ? match[1] : null;
                }
                case 'linux': {
                    const desktopPath = path.join(
                        os.homedir(), '.local', 'share', 'applications', 'erst-protocol.desktop'
                    );
                    const content = await fs.readFile(desktopPath, 'utf8');
                    const match = content.match(/^Exec=(.+)\s+protocol-handler/m);
                    return match ? match[1] : null;
                }
                default:
                    return null;
            }
        } catch {
            return null;
        }
    }

    async diagnose(): Promise<ProtocolDiagnostics> {
        const registered = await this.isRegistered();
        if (!registered) {
            return { registered: false, cliPath: null, pathExists: false, isExecutable: false };
        }

        const cliPath = await this.getRegisteredPath();
        if (!cliPath) {
            return { registered: true, cliPath: null, pathExists: false, isExecutable: false };
        }

        let pathExists = false;
        let isExecutable = false;

        try {
            await fs.access(cliPath);
            pathExists = true;
        } catch {
            return { registered: true, cliPath, pathExists: false, isExecutable: false };
        }

        try {
            if (os.platform() === 'win32') {
                const ext = path.extname(cliPath).toLowerCase();
                isExecutable = ['.exe', '.cmd', '.bat', '.com'].includes(ext);
            } else {
                await fs.access(cliPath, fsConstants.X_OK);
                isExecutable = true;
            }
        } catch {
            // File exists but is not executable
        }

        return { registered: true, cliPath, pathExists, isExecutable };
    }
}
