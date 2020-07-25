using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.IO;
using System.Security.Principal;
using System.Security.AccessControl;

namespace ServicePrivilegeEscalation {

    public enum Attack {
        CHANGE_PERMISSIONS,
        TAKE_OWNERSHIP,
        CREATE_FOLDER,
        CREATE_FILE,
        REPLACE_FILE,
        REPLACE_FILE_CONTENTS,
        REPLACE_FOLDER,
        PUT_DLL
    }

    public struct AttackContext {
        public Attack attack;
        public string path;

        public AttackContext(Attack attack, string path) : this() {
            this.attack = attack;
            this.path = path;
        }
    }

    class Program {

        static bool CheckFileSystemAccessRight(FileSystemAccessRule rule, FileSystemRights right) {
            return (right & rule.FileSystemRights) == right;
        }


        // TODO: Service executable paths at external locations. Check if volume is mounted?

        static List<AttackContext> CheckPath(string executable_path, string path_name) {
            var executable_path_is_quoted = Regex.IsMatch(input: path_name, pattern: Regex.Escape("\"" + executable_path + "\""));

            var identity = WindowsIdentity.GetCurrent();

            var current_path = executable_path;
            var parent_path = Path.GetDirectoryName(path: current_path);
            var current_is_file = true;

            var attack_contexts = new List<AttackContext>();

            do {
                AuthorizationRuleCollection current_rules = null;

                try {
                    if (current_is_file) {
                        current_rules = File
                            .GetAccessControl(
                                path: current_path,
                                includeSections: AccessControlSections.Access
                            )
                            .GetAccessRules(
                                includeExplicit: true,
                                includeInherited: true,
                                targetType: typeof(System.Security.Principal.SecurityIdentifier)
                            )
                        ;
                    } else {
                        current_rules = Directory
                            .GetAccessControl(
                                path: current_path,
                                includeSections: AccessControlSections.Access
                            )
                            .GetAccessRules(
                                includeExplicit: true,
                                includeInherited: true,
                                targetType: typeof(System.Security.Principal.SecurityIdentifier)
                            )
                        ;
                    }
                } catch (FileNotFoundException) {
                } catch (DirectoryNotFoundException) {
                } catch (InvalidOperationException) {
                } catch (UnauthorizedAccessException) { }

                AuthorizationRuleCollection parent_rules = null;

                try {
                    parent_rules = Directory
                        .GetAccessControl(
                            path: parent_path, includeSections: AccessControlSections.Access
                        )
                        .GetAccessRules(
                            includeExplicit: true,
                            includeInherited: true,
                            targetType: typeof(System.Security.Principal.SecurityIdentifier)
                        )
                    ;
                } catch (DirectoryNotFoundException) {
                } catch (ArgumentNullException) {
                } catch (InvalidOperationException) {
                } catch (UnauthorizedAccessException) { }

                var current_path_is_deletable = false;

                if (current_rules != null) {
                    foreach (FileSystemAccessRule rule in current_rules) {
                        if (rule.AccessControlType != AccessControlType.Allow)
                            continue;

                        if (!identity.Groups.Contains(identity: rule.IdentityReference) && !rule.IdentityReference.Value.Equals(identity.User.ToString()))
                            continue;

                        if (CheckFileSystemAccessRight(rule: rule, right: FileSystemRights.Delete))
                            current_path_is_deletable = true;

                        if (CheckFileSystemAccessRight(rule: rule, right: FileSystemRights.ChangePermissions))
                            attack_contexts.Add(new AttackContext(attack: Attack.CHANGE_PERMISSIONS, path: current_path));

                        if (CheckFileSystemAccessRight(rule: rule, right: FileSystemRights.TakeOwnership))
                            attack_contexts.Add(new AttackContext(attack: Attack.TAKE_OWNERSHIP, path: current_path));

                        if (current_is_file && CheckFileSystemAccessRight(rule: rule, right: FileSystemRights.WriteData)) {
                            attack_contexts.Add(new AttackContext(attack: Attack.REPLACE_FILE_CONTENTS, path: current_path));
                        }
                    }
                }

                bool can_create_directories = false;
                bool can_create_files = false;

                if (parent_rules != null) {
                    foreach (FileSystemAccessRule rule in parent_rules) {
                        if (rule.AccessControlType != AccessControlType.Allow)
                            continue;

                        if (!identity.Groups.Contains(identity: rule.IdentityReference) && !rule.IdentityReference.Value.Equals(identity.User.ToString()))
                            continue;

                        can_create_directories = can_create_directories || CheckFileSystemAccessRight(
                            rule: rule,
                            right: FileSystemRights.CreateDirectories
                        );

                        can_create_files = can_create_files || CheckFileSystemAccessRight(
                            rule: rule,
                            right: FileSystemRights.CreateFiles
                        );
                    }
                }

                if (current_is_file && can_create_files) {
                    attack_contexts.Add(new AttackContext(attack: Attack.PUT_DLL, path: parent_path));

                    if (current_rules == null) {
                        attack_contexts.Add(new AttackContext(attack: Attack.CREATE_FILE, path: current_path));
                    } else if (current_path_is_deletable) {
                        attack_contexts.Add(new AttackContext(attack: Attack.REPLACE_FILE, path: current_path));
                    }
                }

                if (!current_is_file && can_create_directories) {
                    if (current_rules == null) {
                        attack_contexts.Add(new AttackContext(attack: Attack.CREATE_FOLDER, path: current_path));
                    } else if (current_path_is_deletable) {
                        attack_contexts.Add(new AttackContext(attack: Attack.REPLACE_FOLDER, path: current_path));
                    }
                }

                var name = Path.GetFileName(path: current_path);
                if (!executable_path_is_quoted && name.Contains(' ') && can_create_files) {
                    attack_contexts.Add(
                        new AttackContext(
                            attack: Attack.CREATE_FILE,
                            path: Path.Combine(path1: parent_path, path2: name.Split(' ')[0])
                        )
                    );
                }

                current_path = parent_path;
                parent_path = Path.GetDirectoryName(path: parent_path);

                current_is_file = false;
            } while (!String.IsNullOrEmpty(current_path));

            return attack_contexts;
        }

        static void Main(string[] args) {

            foreach (var result in new ManagementObjectSearcher(@"root\cimv2", "SELECT * FROM win32_service").Get()) {
                if (result["PathName"] == null)
                    continue;

                var path_name = result["PathName"].ToString();

                Match executable_path_match = Regex.Match(
                    input: path_name,
                    pattern: @"^.*([a-z]:\\.*\\[^<>:/\\|?*""]+).*$",
                    options: RegexOptions.IgnoreCase
                );

                if (executable_path_match.Value == String.Empty) {
                    Console.Error.WriteLine("Path name did not match executable path pattern: {0}", path_name);
                    continue;
                }

                String executable_path = executable_path_match.Groups[1].ToString();
                var attack_contexts = CheckPath(executable_path: executable_path, path_name: path_name);

                if (attack_contexts.Count != 0) {
                    Console.WriteLine("Name: {0}, Executable path: {1}", result["Name"], executable_path);
                    foreach (var attack_context in attack_contexts)
                        Console.WriteLine("Attack: {0}, Path: {1}", attack_context.attack, attack_context.path);
                    Console.WriteLine();
                }
            }
        }
    }
}
