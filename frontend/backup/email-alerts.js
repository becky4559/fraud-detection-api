// Email Alert System for LogSense
const EMAIL_CONFIG = {
    recipient: 'rebeccabosibori589@gmail.com',
    enabled: true,
    alertTypes: {
        highRisk: true,
        mediumRisk: true,
        systemAlert: true,
        weeklyReport: true,
        fraudDetected: true
    },
    schedule: 'realtime'
};

// Simulate sending email alerts
function sendEmailAlert(subject, message, priority = 'normal') {
    if (!EMAIL_CONFIG.enabled) return;
    
    const alertData = {
        to: EMAIL_CONFIG.recipient,
        subject: `[LogSense] ${subject}`,
        body: message,
        priority: priority,
        timestamp: new Date().toISOString(),
        system: 'fraud-detection'
    };
    
    console.log('Email Alert Sent:', alertData);
    
    // In a real implementation, this would call an email service
    // For now, we'll log it and show a confirmation
    showAlertConfirmation(subject);
    
    return alertData;
}

// Alert templates
const ALERT_TEMPLATES = {
    highRisk: (transaction) => `
        HIGH RISK TRANSACTION DETECTED!
        
        Transaction Details:
        - Amount: $${transaction.amount}
        - User: ${transaction.user_id}
        - Risk Level: ${transaction.risk_level}
        - Probability: ${(transaction.fraud_probability * 100).toFixed(1)}%
        - Time: ${new Date(transaction.timestamp).toLocaleString()}
        
        Action Required: Review immediately!
        
        LogSense Fraud Detection System
    `,
    
    fraudTypeDetected: (fraudType, count) => `
        FRAUD PATTERN DETECTED!
        
        Type: ${fraudType.name.toUpperCase()}
        Severity: ${fraudType.severity}
        Cases Today: ${count}
        Description: ${fraudType.description}
        
        Monitor this pattern closely.
        
        LogSense Fraud Detection System
    `,
    
    systemAlert: (message) => `
        SYSTEM ALERT
        
        ${message}
        
        Check the dashboard for details.
        
        LogSense Fraud Detection System
    `,
    
    weeklyReport: (stats) => `
        WEEKLY FRAUD REPORT
        
        Period: ${stats.period}
        Total Transactions: ${stats.total_transactions}
        Fraud Cases: ${stats.fraud_cases}
        Detection Rate: ${stats.detection_rate}%
        Amount Saved: $${stats.amount_saved}
        
        Top Fraud Types:
        ${stats.top_fraud_types.map((type, i) => `${i+1}. ${type.name}: ${type.count} cases`).join('\n')}
        
        View detailed report in dashboard.
        
        LogSense Fraud Detection System
    `
};

// Send alert for high-risk transaction
function sendHighRiskAlert(transaction) {
    if (!EMAIL_CONFIG.alertTypes.highRisk) return;
    
    const subject = `High Risk Transaction: $${transaction.amount}`;
    const message = ALERT_TEMPLATES.highRisk(transaction);
    
    return sendEmailAlert(subject, message, 'high');
}

// Send fraud type alert
function sendFraudTypeAlert(fraudType, count) {
    if (!EMAIL_CONFIG.alertTypes.fraudDetected) return;
    
    const subject = `${fraudType.severity} Risk: ${fraudType.name} Detected`;
    const message = ALERT_TEMPLATES.fraudTypeDetected(fraudType, count);
    
    return sendEmailAlert(subject, message, fraudType.severity.toLowerCase());
}

// Send system alert
function sendSystemAlert(message) {
    if (!EMAIL_CONFIG.alertTypes.systemAlert) return;
    
    const subject = 'System Notification';
    return sendEmailAlert(subject, message);
}

// Send weekly report
function sendWeeklyReport(stats) {
    if (!EMAIL_CONFIG.alertTypes.weeklyReport) return;
    
    const subject = `Weekly Fraud Report: ${stats.period}`;
    const message = ALERT_TEMPLATES.weeklyReport(stats);
    
    return sendEmailAlert(subject, message);
}

// Test alert function
function testEmailAlert() {
    const testTransaction = {
        amount: 15000,
        user_id: 'test_user_001',
        risk_level: 'HIGH',
        fraud_probability: 0.85,
        timestamp: new Date().toISOString()
    };
    
    const alert = sendHighRiskAlert(testTransaction);
    alert('Test alert sent successfully! Check console for details.');
    
    return alert;
}

// Show confirmation
function showAlertConfirmation(subject) {
    const toast = document.createElement('div');
    toast.className = 'email-toast';
    toast.innerHTML = `
        <div style="
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #6366f1;
            color: white;
            padding: 15px 20px;
            border-radius: 10px;
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.4);
            z-index: 9999;
            max-width: 400px;
            animation: slideIn 0.3s ease;
        ">
            <div class="d-flex align-items-center">
                <i class="fas fa-paper-plane fa-lg me-3"></i>
                <div>
                    <div class="fw-bold">Alert Sent</div>
                    <div class="small">${subject}</div>
                    <div class="small mt-1">To: ${EMAIL_CONFIG.recipient}</div>
                </div>
                <button class="btn-close btn-close-white ms-auto" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        </div>
    `;
    
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
}

// Initialize email alerts
document.addEventListener('DOMContentLoaded', function() {
    console.log('Email Alert System Ready for:', EMAIL_CONFIG.recipient);
    
    // Send welcome alert on first load
    if (!localStorage.getItem('logsense_welcomed')) {
        setTimeout(() => {
            sendSystemAlert('Welcome to LogSense Fraud Detection System!\n\nYour dashboard is now active and monitoring for fraudulent activities.');
            localStorage.setItem('logsense_welcomed', 'true');
        }, 3000);
    }
});

// Export for use in other files
window.EmailAlerts = {
    sendHighRiskAlert,
    sendFraudTypeAlert,
    sendSystemAlert,
    sendWeeklyReport,
    testEmailAlert,
    config: EMAIL_CONFIG
};
