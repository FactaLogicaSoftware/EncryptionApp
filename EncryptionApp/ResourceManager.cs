using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;

namespace Encryption_App
{
    internal static class ResourceManager
    {
        internal static Dictionary<string, Assembly> GetAssemblies(params string[] simpleNames)
        {
            var assemblies = new Dictionary<string, Assembly>();
            foreach (string name in simpleNames)
            {
                Assembly loadedAsm = null;

                try
                {
                    if (File.Exists(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), name)))
                    {
                        loadedAsm = Assembly.LoadFile(Path.Combine(RuntimeEnvironment.GetRuntimeDirectory(), name));
                    }

                    if (File.Exists(name))
                    {
                        loadedAsm = Assembly.LoadFile(name);
                    }
                }
                catch (FileLoadException e)
                {
                    FileStatics.WriteToLogFile(e);
                    MessageBox.Show(
                        $"Error loading assemblies - assembly \"{e.FileName}\" could be found but not loaded");

                    loadedAsm = null;
                }
                catch (BadImageFormatException e)
                {
                    FileStatics.WriteToLogFile(e);
                    MessageBox.Show(
                        $"Error loading assemblies - assembly \"{e.FileName}\" is corrupted");

                    loadedAsm = null;
                }

                assemblies.Add(name, loadedAsm);
            }

            return assemblies;
        }
    }
}