// Fetch and display messages from the backend
function fetchMessages() {
    fetch('/api/messages')
    .then(response => response.json())
    .then(data => {
        const messagesContainer = document.getElementById('data');
        messagesContainer.innerHTML = ''; // Clear previous content
        data.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.textContent = `${message.id}: ${message.content}`;
            messagesContainer.appendChild(messageElement);
        });
    })
    .catch(error => console.error('Error fetching messages:', error));
}

// Trigger insertion of random data
function insertMessage() {
    fetch('/api/insert', { method: 'POST' })
    .then(() => {
        console.log('Message inserted');
        fetchMessages(); // Refresh messages
    })
    .catch(error => console.error('Error inserting message:', error));
}

// Fetch messages on page load
document.addEventListener('DOMContentLoaded', () => {
    fetchMessages();
    document.getElementById('insertButton').addEventListener('click', insertMessage);
});
