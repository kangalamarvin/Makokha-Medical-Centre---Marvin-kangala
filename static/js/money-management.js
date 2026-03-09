/**
 * Money Management Summary Calculator
 * Calculates total income (money entering system) and expenses (money leaving system)
 */

const MoneyManagement = {
    /**
     * Calculate total income from all sources
     * INCOME = Lab payments + Sales + Debtor payments + Service revenue
     */
    calculateTotalIncome() {
        let totalIncome = 0;
        
        // Income from patient services/labs (from the data in debtors table - amount_paid)
        // Income from sales/services rendered (money coming in from patients)
        // Parse debtor data to get payments received
        const debtorRows = document.querySelectorAll('#debtors-table tbody tr');
        debtorRows.forEach(row => {
            const amountPaidCell = row.querySelector('td:nth-child(4)'); // Amount Paid column
            if (amountPaidCell) {
                const amount = this.parseMoneyValue(amountPaidCell.textContent);
                totalIncome += amount;
            }
        });
        
        return totalIncome;
    },

    /**
     * Calculate total expenses from all sources
     * EXPENSES = Drawings + Bills (all) + Purchases + Payroll (all) + Debtor arrears
     */
    calculateTotalExpenses() {
        let totalExpenses = 0;
        
        // Personal drawings (money out for owner)
        const drawingRows = document.querySelectorAll('#drawings-table tbody tr');
        drawingRows.forEach(row => {
            const amountCell = row.querySelector('td:nth-child(2)'); // Amount column
            if (amountCell) {
                const amount = this.parseMoneyValue(amountCell.textContent);
                totalExpenses += amount;
            }
        });
        
        // Bills/Expenses (all bills, regardless of paid status)
        const billRows = document.querySelectorAll('#bills-table tbody tr');
        billRows.forEach(row => {
            const amountCell = row.querySelector('td:nth-child(2)'); // Amount column
            if (amountCell) {
                const amount = this.parseMoneyValue(amountCell.textContent);
                totalExpenses += amount;
            }
        });
        
        // Purchases (all business purchases)
        const purchaseRows = document.querySelectorAll('#purchases-table tbody tr');
        purchaseRows.forEach(row => {
            const amountCell = row.querySelector('td:nth-child(2)'); // Amount column
            if (amountCell) {
                const amount = this.parseMoneyValue(amountCell.textContent);
                totalExpenses += amount;
            }
        });
        
        // Payroll (all salary payments)
        const payrollRows = document.querySelectorAll('#payroll-table tbody tr');
        payrollRows.forEach(row => {
            const salaryCell = row.querySelector('td:nth-child(3)'); // Salary column
            if (salaryCell) {
                const amount = this.parseMoneyValue(salaryCell.textContent);
                totalExpenses += amount;
            }
        });
        
        return totalExpenses;
    },

    /**
     * Calculate pending payments
     * PENDING = Bills pending + Payroll due (not fully paid)
     */
    calculatePendingPayments() {
        let pendingCount = 0;
        
        // Count pending bills
        const billRows = document.querySelectorAll('#bills-table tbody tr');
        billRows.forEach(row => {
            const statusCell = row.querySelector('td:nth-child(4)'); // Status column
            if (statusCell && (statusCell.textContent.includes('Pending') || statusCell.textContent.includes('Overdue'))) {
                pendingCount++;
            }
        });
        
        // Count payroll with arrears
        const payrollRows = document.querySelectorAll('#payroll-table tbody tr');
        payrollRows.forEach(row => {
            const arrearsCell = row.querySelector('td:nth-child(5)'); // Arrears column
            if (arrearsCell) {
                const amount = this.parseMoneyValue(arrearsCell.textContent);
                if (amount > 0) {
                    pendingCount++;
                }
            }
        });
        
        return pendingCount;
    },

    /**
     * Parse money value from text
     * Handles formats like "Ksh 1,234.56" or "$ 1,234.56"
     */
    parseMoneyValue(text) {
        if (!text) return 0;
        // Remove currency symbols, spaces, and extract the number
        const match = text.match(/[\d,]+\.?\d*/);
        if (match) {
            return parseFloat(match[0].replace(/,/g, ''));
        }
        return 0;
    },

    /**
     * Format money value for display
     */
    formatMoney(value) {
        return 'Ksh ' + value.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    /**
     * Update all summary cards with calculated values
     */
    updateSummary() {
        const totalIncome = this.calculateTotalIncome();
        const totalExpenses = this.calculateTotalExpenses();
        const netProfit = totalIncome - totalExpenses;
        const pendingPayments = this.calculatePendingPayments();
        
        // Update DOM elements
        const incomeElement = document.getElementById('total-income');
        const expensesElement = document.getElementById('total-expenses');
        const profitElement = document.getElementById('net-profit');
        const pendingElement = document.getElementById('pending-payments');
        
        if (incomeElement) {
            incomeElement.textContent = this.formatMoney(totalIncome);
        }
        
        if (expensesElement) {
            expensesElement.textContent = this.formatMoney(totalExpenses);
        }
        
        if (profitElement) {
            profitElement.textContent = this.formatMoney(netProfit);
            // Change color based on profit/loss
            if (netProfit < 0) {
                profitElement.parentElement.parentElement.style.borderLeft = '4px solid #dc3545';
            } else {
                profitElement.parentElement.parentElement.style.borderLeft = '4px solid #28a745';
            }
        }
        
        if (pendingElement) {
            pendingElement.textContent = pendingPayments.toString();
        }
    },

    /**
     * Initialize the money management module
     */
    init() {
        // Update summary on page load
        this.updateSummary();
        
        // Observe for changes in tables and update summary
        const observer = new MutationObserver(() => {
            this.updateSummary();
        });
        
        // Watch all tables for changes
        const tables = document.querySelectorAll('table');
        tables.forEach(table => {
            observer.observe(table, {
                childList: true,
                subtree: true,
                characterData: true
            });
        });
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    MoneyManagement.init();
});
