// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace Security.Cryptography
{
    /// <summary>
    ///     Context object used to check that correct locks are held upon access to a crypto object
    /// </summary>
    public class CryptographyLockContext<T> where T : class
    {
        private T m_algorithm;
        private object m_parameter;

        internal CryptographyLockContext(T algorithm, object parameter)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            m_algorithm = algorithm;
            m_parameter = parameter;
        }

        /// <summary>
        ///     Algorithm the lock is being checked on
        /// </summary>
        public T Algorithm
        {
            get { return m_algorithm; }
        }

        /// <summary>
        ///     Optional extra information for checking the lock
        /// </summary>
        public object Parameter
        {
            get { return m_parameter; }
        }
    }
}
