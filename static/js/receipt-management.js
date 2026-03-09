/**
 * Receipt Management System
 * Handles receipt generation, display, download, and printing for all payment types
 */

window.receiptManagement = {
    currentReceipt: null,

    escapeHtml: function(value) {
        const s = String(value ?? '');
        return s
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    },
    
    /**
     * Generate receipt after payment
     * @param {string} paymentType - Type of payment (payroll, debtor, bill)
     * @param {number} recordId - ID of the related record
     * @param {object} paymentData - Payment details
     * @returns {Promise} Receipt data
     */
    generateReceipt: function(paymentType, recordId, paymentData) {
        return fetch(`/admin/generate_receipt/${paymentType}/${recordId}`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': moneyManagement.getCSRFToken(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(paymentData)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                this.currentReceipt = data.receipt;
                return data.receipt;
            }
            throw new Error(data.error || 'Failed to generate receipt');
        })
        .catch(error => {
            console.error('Receipt generation error:', error);
            moneyManagement.showAlert('danger', 'Failed to generate receipt: ' + error.message);
            throw error;
        });
    },

    /**
     * Fetch receipt by ID
     */
    fetchReceipt: function(receiptId) {
        return fetch(`/admin/get_receipt/${receiptId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    this.currentReceipt = data.receipt;
                    return data.receipt;
                }
                throw new Error(data.error || 'Failed to fetch receipt');
            })
            .catch(error => {
                console.error('Error fetching receipt:', error);
                throw error;
            });
    },

    /**
     * Display receipt in modal
     */
    displayReceipt: function(receipt) {
        if (!receipt) {
            receipt = this.currentReceipt;
        }
        
        if (!receipt) {
            moneyManagement.showAlert('danger', 'No receipt to display');
            return;
        }

        const receiptContent = document.getElementById('receipt-content');
        if (!receiptContent) {
            console.error('Receipt content container not found');
            return;
        }

        let receiptHTML = `
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <div style="text-align: center; border-bottom: 2px solid #333; padding-bottom: 15px; margin-bottom: 15px;">
                    <h2 style="margin: 5px 0; font-size: 18px;">MAKOKHA MEDICAL CENTRE</h2>
                    <p style="margin: 2px 0; font-size: 11px;">P.O. Box 123, Nairobi, Kenya</p>
                    <p style="margin: 2px 0; font-size: 11px;">Tel: +254 7XXXXXXXX</p>
                </div>
                
                <div style="text-align: center; margin-bottom: 15px;">
                    <h3 style="margin: 5px 0; font-size: 16px;">RECEIPT</h3>
                    <p style="margin: 2px 0; font-weight: bold; color: #667eea;">Receipt #: ${this.escapeHtml(receipt.receipt_number)}</p>
                </div>
                
                <div style="margin-bottom: 15px; font-size: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span><strong>Date:</strong></span>
                        <span>${this.escapeHtml(receipt.payment_date || receipt.created_at)}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span><strong>Amount:</strong></span>
                        <span style="color: #28a745; font-weight: bold;">Ksh ${this.formatMoney(receipt.amount)}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span><strong>Payment Method:</strong></span>
                        <span>${this.escapeHtml(receipt.payment_method || 'Cash')}</span>
                    </div>
                    ${receipt.description ? `
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span><strong>Description:</strong></span>
                        <span>${this.escapeHtml(receipt.description)}</span>
                    </div>
                    ` : ''}
                </div>
                
                <div style="border-top: 1px dashed #999; border-bottom: 1px dashed #999; padding: 15px 0; margin: 15px 0;">
                    <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 8px;">
                        <span><strong>Issued By:</strong></span>
                        <span>${this.escapeHtml(receipt.issued_by)}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 12px;">
                        <span><strong>Status:</strong></span>
                        <span style="color: #28a745; font-weight: bold;">? Confirmed</span>
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 20px; padding: 20px; border: 2px dashed #ccc; border-radius: 8px; background: #f9f9f9;">
                    <p style="margin: 5px 0; font-size: 11px; color: #666;">Official Hospital Stamp</p>
                    <div style="width: 60px; height: 60px; margin: 10px auto; border: 2px solid #ddd; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: #ccc; font-weight: bold;">
                        [STAMP]
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 15px; font-size: 10px; color: #999;">
                    <p style="margin: 2px 0;">Thank you for your payment</p>
                    <p style="margin: 2px 0;">Keep this receipt for your records</p>
                </div>
            </div>
        `;
        
        receiptContent.innerHTML = receiptHTML;
        moneyManagement.openModal('receipt-view');
    },

    /**
     * Show payment confirmation with receipt details
     */
    showPaymentConfirmation: function(receipt, message) {
        if (!receipt) {
            receipt = this.currentReceipt;
        }

        if (!receipt) {
            moneyManagement.showAlert('danger', 'No receipt data available');
            return;
        }

        document.getElementById('confirmation-message').textContent = message || 'Your payment has been recorded successfully.';
        document.getElementById('conf-receipt-number').textContent = receipt.receipt_number;
        document.getElementById('conf-receipt-amount').textContent = 'Ksh ' + this.formatMoney(receipt.amount);
        document.getElementById('conf-receipt-date').textContent = receipt.payment_date || receipt.created_at;
        document.getElementById('conf-receipt-issued-by').textContent = receipt.issued_by;

        moneyManagement.openModal('receipt-confirmation');
    },

    /**
     * Download receipt as PDF
     */
    downloadReceiptPDF: function(receiptId) {
        if (!receiptId && this.currentReceipt) {
            receiptId = this.currentReceipt.id;
        }

        if (!receiptId) {
            moneyManagement.showAlert('danger', 'No receipt to download');
            return;
        }

        window.location.href = `/admin/download_receipt/${receiptId}`;
    },

    /**
     * Download current receipt as PDF
     */
    downloadCurrentReceiptPDF: function() {
        this.downloadReceiptPDF();
    },

    /**
     * Print receipt
     */
    printReceipt: function(receiptId) {
        if (!receiptId && this.currentReceipt) {
            receiptId = this.currentReceipt.id;
        }

        if (!receiptId) {
            moneyManagement.showAlert('danger', 'No receipt to print');
            return;
        }

        window.open(`/admin/print_receipt/${receiptId}`, '_blank', 'width=600,height=800');
    },

    /**
     * Print current receipt
     */
    printCurrentReceipt: function() {
        this.printReceipt();
    },

    /**
     * Get all receipts for a record
     */
    getReceiptsForRecord: function(recordType, recordId) {
        return fetch(`/admin/get_receipts/${recordType}/${recordId}`)
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    return data.receipts || [];
                }
                throw new Error(data.error || 'Failed to fetch receipts');
            })
            .catch(error => {
                console.error('Error fetching receipts:', error);
                return [];
            });
    },

    /**
     * Display list of receipts
     */
    displayReceiptsList: function(receipts, container) {
        if (!receipts || receipts.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: #999;">No receipts available</p>';
            return;
        }

        let html = '<div style="display: flex; flex-direction: column; gap: 10px;">';
        
        receipts.forEach(receipt => {
            html += `
                <div style="border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px; background: #fafafa;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <strong style="color: #667eea;">${this.escapeHtml(receipt.receipt_number)}</strong>
                        <span style="font-size: 12px; color: #999;">${this.escapeHtml(receipt.created_at)}</span>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 12px;">
                        <div><span style="color: #666;">Amount:</span> <strong style="color: #28a745;">Ksh ${this.formatMoney(receipt.amount)}</strong></div>
                        <div><span style="color: #666;">Method:</span> ${this.escapeHtml(receipt.payment_method || 'Cash')}</div>
                    </div>
                    <div style="margin-top: 8px; display: flex; gap: 8px;">
                        <button class="btn btn-primary" onclick="receiptManagement.viewReceipt(${receipt.id})" style="font-size: 11px; padding: 6px 12px;">
                            <i class="fas fa-eye"></i> View
                        </button>
                        <button class="btn btn-primary" onclick="receiptManagement.printReceipt(${receipt.id})" style="font-size: 11px; padding: 6px 12px;">
                            <i class="fas fa-print"></i> Print
                        </button>
                        <button class="btn btn-primary" onclick="receiptManagement.downloadReceiptPDF(${receipt.id})" style="font-size: 11px; padding: 6px 12px;">
                            <i class="fas fa-download"></i> PDF
                        </button>
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        container.innerHTML = html;
    },

    /**
     * View a specific receipt
     */
    viewReceipt: function(receiptId) {
        this.fetchReceipt(receiptId)
            .then(receipt => {
                this.displayReceipt(receipt);
            })
            .catch(error => {
                moneyManagement.showAlert('danger', 'Failed to load receipt');
            });
    },

    /**
     * Format currency value
     */
    formatMoney: function(amount) {
        return parseFloat(amount).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    },

    /**
     * Handle payment completion with receipt
     */
    handlePaymentCompletion: function(paymentType, recordId, paymentData, successMessage) {
        // Generate receipt
        return this.generateReceipt(paymentType, recordId, paymentData)
            .then(receipt => {
                // Show confirmation with receipt
                this.showPaymentConfirmation(receipt, successMessage);
                return receipt;
            })
            .catch(error => {
                // Even if receipt generation fails, show success alert
                moneyManagement.showAlert('success', successMessage || 'Payment recorded successfully');
                return null;
            });
    },

    /**
     * Email receipt to recipient
     */
    emailReceipt: function(receiptId, recipientEmail) {
        return fetch(`/admin/email_receipt/${receiptId}`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': moneyManagement.getCSRFToken(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: recipientEmail
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                moneyManagement.showAlert('success', 'Receipt sent to email successfully');
                return true;
            }
            throw new Error(data.error || 'Failed to send email');
        })
        .catch(error => {
            console.error('Error sending email:', error);
            moneyManagement.showAlert('danger', 'Failed to send receipt: ' + error.message);
            return false;
        });
    }
};
