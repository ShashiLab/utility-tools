document.addEventListener('DOMContentLoaded', function() {
    const ITERATION_COUNT = 310000;
    const KEY_LENGTH = 256;
    const SALT_LENGTH = 16;
    const NONCE_LENGTH = 12;
    const GCM_TAG_LENGTH = 128;
    const SHORT_IO_API_KEY = 'pk_muoTHarWdhmULPqC';
    const SHORT_IO_DOMAIN = 'open.shashi.app';
    const STORAGE_KEY = 'textEncryptorData';

    const tabs = document.querySelectorAll('.tab');
    const actionButton = document.getElementById('actionButton');
    const clearButton = document.getElementById('clearButton');
    const textInput = document.getElementById('text');
    const passwordInput = document.getElementById('password');
    const togglePasswordButton = document.getElementById('togglePassword');
    const resultContainer = document.getElementById('resultContainer');
    const resultType = document.getElementById('resultType');
    const resultContent = document.getElementById('resultContent');
    const copyButton = document.getElementById('copyButton');
    const downloadButton = document.getElementById('downloadButton');
    const shareButton = document.getElementById('shareButton');
    const notification = document.getElementById('notification');

    let currentOperation = 'encrypt';

    function saveFormData() {
        const formData = {
            text: textInput.value,
            operation: currentOperation,
            result: resultContainer.classList.contains('visible') ? resultContent.textContent : null
        };
        
        localStorage.setItem(STORAGE_KEY, JSON.stringify(formData));
    }

    function loadFormData() {
        const savedData = localStorage.getItem(STORAGE_KEY);
        
        if (savedData) {
            try {
                const formData = JSON.parse(savedData);
                
                if (formData.text) {
                    textInput.value = formData.text;
                }
                
                if (formData.operation) {
                    currentOperation = formData.operation;
                    tabs.forEach(tab => {
                        tab.classList.remove('active');
                        if (tab.dataset.tab === currentOperation) {
                            tab.classList.add('active');
                        }
                    });
                    updateUI();
                }
                
                if (formData.result) {
                    resultContent.textContent = formData.result;
                    resultContainer.classList.add('visible');
                }

            } catch (error) {
                console.error('Error loading saved form data:', error);
            }
        }
    }

    function setupAutosave() {
        let textSaveTimeout;
        textInput.addEventListener('input', () => {
            clearTimeout(textSaveTimeout);
            textSaveTimeout = setTimeout(saveFormData, 500);
        });
        
        tabs.forEach(tab => {
            tab.addEventListener('change', saveFormData);
        });
        
        window.addEventListener('beforeunload', saveFormData);
    }

    function getUrlParams() {
        const params = {};
        const urlParams = new URLSearchParams(window.location.search);
        
        if (urlParams.has('mode')) {
            params.mode = urlParams.get('mode').toLowerCase();
        }
        
        if (urlParams.has('text')) {
            params.text = decodeURIComponent(urlParams.get('text'));
        }
        
        if (urlParams.has('password')) {
            params.password = decodeURIComponent(urlParams.get('password'));
        }
        
        return params;
    }

    function applyUrlParams() {
        const params = getUrlParams();
        
        if (params.mode && (params.mode === 'encrypt' || params.mode === 'decrypt')) {
            currentOperation = params.mode;
            tabs.forEach(tab => {
                tab.classList.remove('active');
                if (tab.dataset.tab === currentOperation) {
                    tab.classList.add('active');
                }
            });
            updateUI();
        }
        
        if (params.text) {
            textInput.value = params.text;
        }
        
        if (params.password) {
            passwordInput.value = params.password;
        }
        
        if (params.text && params.password) {
            setTimeout(() => {
                actionButton.click();
            }, 500);
        }
    }

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentOperation = tab.dataset.tab;
            updateUI();
            saveFormData();
        });
    });

    function updateUI() {
        if (currentOperation === 'encrypt') {
            actionButton.innerHTML = '<i class="fas fa-lock"></i> <span>Encrypt</span>';
            resultType.textContent = 'Encryption';
            textInput.placeholder = 'Enter text to encrypt';
        } else {
            actionButton.innerHTML = '<i class="fas fa-unlock"></i> <span>Decrypt</span>';
            resultType.textContent = 'Decryption';
            textInput.placeholder = 'Enter encrypted text to decrypt';
        }
    }

    togglePasswordButton.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePasswordButton.innerHTML = type === 'password' ? 
            '<i class="fas fa-eye"></i>' : 
            '<i class="fas fa-eye-slash"></i>';
    });

    function generateShareableUrl(text, operation, password = '') {
        const baseUrl = window.location.origin + window.location.pathname;
        const params = new URLSearchParams();
        
        params.set('mode', operation);
        params.set('text', encodeURIComponent(text));
        
        if (password) {
            params.set('password', encodeURIComponent(password));
        }
        
        return `${baseUrl}?${params.toString()}`;
    }

    async function createShortUrl(longUrl) {
        try {
            const response = await fetch('https://api.short.io/links/public', {
                method: 'POST',
                headers: {
                    'Authorization': SHORT_IO_API_KEY,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    domain: SHORT_IO_DOMAIN,
                    originalURL: longUrl
                })
            });
            
            if (response.ok) {
                const data = await response.json();
                return data.shortURL;
            } else {
                console.error('Short.io API error:', await response.text());
                return longUrl;
            }
        } catch (error) {
            console.error('Error creating short URL:', error);
            return longUrl;
        }
    }

    function downloadTextFile(text, filename) {
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    actionButton.addEventListener('click', async () => {
        const text = textInput.value.trim();
        const password = passwordInput.value;

        if (!text) {
            showNotification('Please enter text to process', true);
            textInput.focus();
            return;
        }
        
        if (!password) {
            showNotification('Please enter a password', true);
            passwordInput.focus();
            return;
        }

        actionButton.disabled = true;
        const originalButtonText = actionButton.innerHTML;
        actionButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Processing...</span>';

        try {
            let result;
            if (currentOperation === 'encrypt') {
                result = await encryptText(text, password);
            } else {
                result = await decryptText(text, password);
            }
            
            resultContent.textContent = result;
            resultContainer.classList.add('visible');
            showNotification(currentOperation === 'encrypt' ? 'Text encrypted successfully' : 'Text decrypted successfully');
            saveFormData();
        } catch (error) {
            showNotification(error.message, true);
        } finally {
            actionButton.disabled = false;
            actionButton.innerHTML = originalButtonText;
        }
    });

    clearButton.addEventListener('click', () => {
        textInput.value = '';
        passwordInput.value = '';
        resultContainer.classList.remove('visible');
        saveFormData();
        localStorage.removeItem(STORAGE_KEY);
    });

    copyButton.addEventListener('click', () => {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(resultContent.textContent)
                .then(() => {
                    showNotification('Copied to clipboard');
                    copyButton.querySelector('i').className = 'fas fa-check';
                    setTimeout(() => {
                        copyButton.querySelector('i').className = 'fas fa-copy';
                    }, 2000);
                })
                .catch(() => {
                    fallbackCopyToClipboard(resultContent.textContent);
                });
        } else {
            fallbackCopyToClipboard(resultContent.textContent);
        }
    });

    downloadButton.addEventListener('click', () => {
        const filename = currentOperation === 'encrypt' ? 'encrypted-text.txt' : 'decrypted-text.txt';
        downloadTextFile(resultContent.textContent, filename);
        showNotification(`Downloaded as ${filename}`);
    });

    shareButton.addEventListener('click', async () => {
        const shareText = resultContent.textContent;
        const oppositeOperation = currentOperation === 'encrypt' ? 'decrypt' : 'encrypt';
        
        shareButton.disabled = true;
        shareButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Sharing...';
        
        try {
            const longUrl = generateShareableUrl(shareText, oppositeOperation);
            const shortUrl = await createShortUrl(longUrl);
            
            if (navigator.share) {
                await navigator.share({
                    title: 'Encrypted/Decrypted Text',
                    text: 'Check out this encrypted/decrypted text',
                    url: shortUrl
                });
                showNotification('Shared successfully');
            } else {
                await navigator.clipboard.writeText(shortUrl);
                showNotification('Share link copied to clipboard');
            }
        } catch (error) {
            console.error('Error sharing:', error);
            showNotification('Failed to share link', true);
        } finally {
            shareButton.disabled = false;
            shareButton.innerHTML = '<i class="fas fa-share-alt"></i> Share';
        }
    });
    
    function fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                showNotification('Copied to clipboard');
                copyButton.querySelector('i').className = 'fas fa-check';
                setTimeout(() => {
                    copyButton.querySelector('i').className = 'fas fa-copy';
                }, 2000);
            } else {
                showNotification('Failed to copy to clipboard', true);
            }
        } catch (err) {
            showNotification('Failed to copy to clipboard', true);
        }
        
        document.body.removeChild(textArea);
    }

    function showNotification(message, isError = false) {
        notification.textContent = message;
        notification.className = 'notification' + (isError ? ' error' : '');
        notification.classList.add('visible');
        
        const icon = document.createElement('i');
        icon.className = isError ? 'fas fa-exclamation-circle' : 'fas fa-check-circle';
        icon.style.marginRight = '0.5rem';
        notification.prepend(icon);
        
        setTimeout(() => {
            notification.classList.remove('visible');
            setTimeout(() => {
                notification.textContent = '';
            }, 300);
        }, 3000);
    }

    async function encryptText(plaintext, password) {
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
        
        const key = await deriveKey(password, salt);
        
        const encodedText = new TextEncoder().encode(plaintext);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, tagLength: GCM_TAG_LENGTH },
            key,
            encodedText
        );
        
        const ciphertext = new Uint8Array(encrypted);
        
        return `${bytesToHex(salt)}:${bytesToHex(nonce)}:${btoa(String.fromCharCode(...ciphertext))}`;
    }

    async function decryptText(encryptedText, password) {
        const parts = encryptedText.split(':');
        if (parts.length !== 3) throw new Error('Invalid encrypted text format');
        
        const salt = hexToBytes(parts[0]);
        const nonce = hexToBytes(parts[1]);
        
        const ciphertext = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
        
        const key = await deriveKey(password, salt);
        
        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: nonce, tagLength: GCM_TAG_LENGTH },
                key,
                ciphertext
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error('Decryption failed. Invalid password or corrupted data.');
        }
    }

    async function deriveKey(password, salt) {
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: ITERATION_COUNT,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    function bytesToHex(bytes) {
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return bytes;
    }

    document.querySelectorAll('button.primary').forEach(button => {
        button.addEventListener('click', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const circle = document.createElement('span');
            circle.style.position = 'absolute';
            circle.style.backgroundColor = 'rgba(255, 255, 255, 0.3)';
            circle.style.borderRadius = '50%';
            circle.style.width = '0';
            circle.style.height = '0';
            circle.style.top = y + 'px';
            circle.style.left = x + 'px';
            circle.style.transform = 'translate(-50%, -50%)';
            circle.style.transition = 'all 0.5s ease-out';
            
            this.appendChild(circle);
            
            setTimeout(() => {
                const diameter = Math.max(this.clientWidth, this.clientHeight) * 2;
                circle.style.width = diameter + 'px';
                circle.style.height = diameter + 'px';
                circle.style.opacity = '0';
            }, 1);
            
            setTimeout(() => {
                circle.remove();
            }, 500);
        });
    });

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/text-encryptor/service-worker.js')
                .then(registration => {
                    console.log('ServiceWorker registration successful with scope: ', registration.scope);
                })
                .catch(err => {
                    console.log('ServiceWorker registration failed: ', err);
                });
        });
    }

    let sessionTimeoutId;
    const SESSION_TIMEOUT = 15 * 60 * 1000;

    function resetSessionTimeout() {
        clearTimeout(sessionTimeoutId);
        sessionTimeoutId = setTimeout(() => {
            if (passwordInput.value) {
                passwordInput.value = '';
                showNotification('Session expired for security reasons', true);
            }
        }, SESSION_TIMEOUT);
    }

    ['mousedown', 'keypress', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetSessionTimeout);
    });
    
    resetSessionTimeout();

    window.addEventListener('beforeunload', (e) => {
        if (textInput.value && !localStorage.getItem(STORAGE_KEY)) {
            e.preventDefault();
            e.returnValue = '';
            return '';
        }
    });

    updateUI();
    
    applyUrlParams();
    
    if (!getUrlParams().text) {
        loadFormData();
    }
    
    setupAutosave();
});