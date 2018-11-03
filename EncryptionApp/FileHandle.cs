using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Encryption_App
{
    internal class FileHandle
    {
        private FileStream _lockHandle;
        private readonly object _owner;
        private readonly string _filePathToLock;
        private readonly FileShare _share;

        internal FileHandle(object owner, string filePathToLock, FileShare share = FileShare.None)
        {
            this._owner = owner;
            this._filePathToLock = filePathToLock;
            this._share = share;
            this._lockHandle = new FileStream(this._filePathToLock, FileMode.Open, FileAccess.ReadWrite, this._share);
        }

        internal FileStream RequestFileAccess(object callingContext, [CallerMemberName] string name = "")
        {
            return this._owner.GetType().GetMethod(name) != null && this._owner == callingContext ? this._lockHandle : null;
        }

        internal void DestroyFileAccess(object callingContext, [CallerMemberName] string name = "")
        {
            this._lockHandle = null;
        }

        internal void ResetFileAccess(object callingContext, [CallerMemberName] string name = "")
        {
            this._lockHandle = null;
            this._lockHandle = new FileStream(this._filePathToLock, FileMode.Open, FileAccess.ReadWrite, this._share);
        }
    }
}
