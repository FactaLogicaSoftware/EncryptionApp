using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;

namespace Encryption_App
{
    internal class ResourceManager : ManagedSlave
    {
        private readonly object _owner;
        private readonly bool _reportProgress;
        private readonly Dictionary<object, Progress<int>> _progressEventList;

        internal ResourceManager(object owner) : base(owner)
        {
            this._owner = owner;
            this._reportProgress = false;
        }

        internal ResourceManager(object owner, Dictionary<object, Progress<int>> progressEvents) : base(owner)
        {
            this._owner = owner;
            this._progressEventList = progressEvents;
            this._reportProgress = true;
        }

        internal Dictionary<string, Assembly> GetAssemblies(params string[] simpleNames)
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

        internal Dictionary<string, Assembly> GetAssemblies(object callingContext, params string[] simpleNames)
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
                    try
                    {
                        if (this._reportProgress)
                            ((IProgress<int>)this._progressEventList[callingContext]).Report(0);
                    }
                    catch (KeyNotFoundException exception)
                    {
                        throw new InvalidCallerException("Calling context not valid for progress reporting - no respective key found", exception);
                    }

                    loadedAsm = null;
                }
                catch (BadImageFormatException e)
                {
                    FileStatics.WriteToLogFile(e);
                    MessageBox.Show(
                        $"Error loading assemblies - assembly \"{e.FileName}\" is corrupted");
                    try
                    {
                        if (this._reportProgress)
                            ((IProgress<int>)this._progressEventList[callingContext]).Report(0);
                    }
                    catch (KeyNotFoundException exception)
                    {
                        throw new InvalidCallerException("Calling context not valid for progress reporting - no respective key found", exception);
                    }

                    loadedAsm = null;
                }

                assemblies.Add(name, loadedAsm);
            }

            return assemblies;
        }
    }
}
