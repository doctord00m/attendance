function sendHeartbeat() {
    fetch('/heartbeat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status !== "connected") {
            alert("You have been disconnected from the class.");
            window.location.href = "/logout";
        }
    })
    .catch(error => {
        console.error("Error in sending heartbeat:", error);
    });
}

// Send heartbeat every 5 minutes
setInterval(sendHeartbeat, 300000);
