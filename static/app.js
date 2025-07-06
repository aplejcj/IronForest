document.addEventListener('DOMContentLoaded', () => {
    const socket = io("http://127.0.0.1:10000");

    const logContainer = document.getElementById('log-container');

    const addInitialLog = (message, type) => {
        const initialLog = document.createElement('div');
        initialLog.classList.add('log-entry');
        const messageSpan = document.createElement('span');
        messageSpan.classList.add('log-message', type);
        messageSpan.textContent = message;
        initialLog.appendChild(messageSpan);
        logContainer.prepend(initialLog);
    };
    
    socket.on('connect', () => {
        console.log('Successfully connected to IronForest Dashboard!');
        addInitialLog('Successfully connected to IronForest Dashboard!', 'info');
    });

    socket.on('connect_error', () => {
        console.error('Connection failed!');
        addInitialLog('Connection to server failed. Please check if observer_web.py is running.', 'blacklist');
    });

    socket.on('new_log', function(data) {
        const logEntry = document.createElement('div');
        logEntry.classList.add('log-entry');
        
        const timeSpan = document.createElement('span');
        timeSpan.classList.add('log-time');
        timeSpan.textContent = `[${data.time}] `;

        const messageSpan = document.createElement('span');
        messageSpan.classList.add('log-message');
        messageSpan.textContent = data.message;
        
        if (data.message.includes('DETECTED')) {
            messageSpan.classList.add('detect');
        } else if (data.message.includes('NETWORK BLACKLISTED')) {
            messageSpan.classList.add('blacklist');
        } else if (data.message.includes('Node started')) {
            messageSpan.classList.add('info');
        }

        logEntry.appendChild(timeSpan);
        logEntry.appendChild(messageSpan);
        
        logContainer.prepend(logEntry);
    });

    addInitialLog('Waiting for logs from nodes...', 'info');
});