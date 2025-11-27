// ThreatIntellAI Main JavaScript

// Global utility functions
const ThreatIntellAI = {
    // Show notification
    showNotification: function(message, type = 'info') {
        const alertClass = {
            'success': 'alert-success',
            'error': 'alert-danger',
            'warning': 'alert-warning',
            'info': 'alert-info'
        }[type] || 'alert-info';

        const notification = document.createElement('div');
        notification.className = `alert ${alertClass} alert-dismissible fade show`;
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Add to page
        const container = document.createElement('div');
        container.style.position = 'fixed';
        container.style.top = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        container.style.minWidth = '300px';
        container.appendChild(notification);
        
        document.body.appendChild(container);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            if (container.parentNode) {
                container.parentNode.removeChild(container);
            }
        }, 5000);
    },

    // Format risk level with icons
    formatRiskLevel: function(riskLevel) {
        const icons = {
            'malicious': 'fa-exclamation-triangle text-danger',
            'suspicious': 'fa-exclamation-circle text-warning',
            'safe': 'fa-check-circle text-success',
            'high': 'fa-exclamation-triangle text-danger',
            'medium': 'fa-exclamation-circle text-warning',
            'low': 'fa-check-circle text-success'
        };
        
        const iconClass = icons[riskLevel.toLowerCase()] || 'fa-question-circle text-secondary';
        return `<i class="fas ${iconClass}"></i> ${riskLevel}`;
    },

    // Format timestamp
    formatTimestamp: function(timestamp) {
        return new Date(timestamp).toLocaleString();
    },

    // Download file
    downloadFile: function(url, filename) {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Add loading states to all forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const button = this.querySelector('button[type="submit"]');
            if (button) {
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
                button.disabled = true;
                
                // Revert after 30 seconds if still processing
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }, 30000);
            }
        });
    });

    // Add copy to clipboard functionality
    const copyButtons = document.querySelectorAll('[data-copy]');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const text = this.getAttribute('data-copy');
            navigator.clipboard.writeText(text).then(() => {
                ThreatIntellAI.showNotification('Copied to clipboard!', 'success');
            });
        });
    });

    console.log('ThreatIntellAI Frontend Loaded 🚀');
});

// Error handling
window.addEventListener('error', function(e) {
    console.error('Frontend Error:', e.error);
    ThreatIntellAI.showNotification('An error occurred. Please try again.', 'error');
});

// Export for global access
window.ThreatIntellAI = ThreatIntellAI;