/**
 * Practical Examples - MMC Loading Indicator
 * These examples show real-world usage patterns in the Makokha Medical Centre system
 */

// ============================================================================
// EXAMPLE 1: Form Submission with Validation
// ============================================================================
function submitFormWithLoader() {
    const form = document.querySelector('#my-form');
    
    // Show loading state
    MMCLoader.show('Submitting Form', 'Validating your information...');
    
    // Simulate form submission
    fetch(form.action, {
        method: 'POST',
        body: new FormData(form),
        headers: {
            'X-CSRFToken': document.querySelector('[name="csrf_token"]')?.value || ''
        }
    })
    .then(response => {
        if (response.ok) {
            // Success state
            MMCLoader.setStatus('complete');
            MMCLoader.updateText('Form Submitted', 'Your request has been recorded');
            
            // Auto-transition to done and hide
            setTimeout(() => {
                MMCLoader.setStatus('done');
                MMCLoader.hide(2000);
                
                // Optional: Redirect after success
                // window.location.href = '/dashboard';
            }, 1000);
        } else {
            throw new Error('Form submission failed');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        MMCLoader.updateText('Error', error.message);
        MMCLoader.hide(3000);
    });
}

// ============================================================================
// EXAMPLE 2: File Upload Progress
// ============================================================================
function uploadFileWithLoader(file) {
    MMCLoader.show('Uploading File', `Uploading ${file.name}...`);
    
    const formData = new FormData();
    formData.append('file', file);
    
    fetch('/api/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            MMCLoader.setStatus('complete');
            MMCLoader.updateText('Upload Complete', 'File saved successfully');
            
            setTimeout(() => {
                MMCLoader.setStatus('done');
                MMCLoader.hide(2000);
            }, 800);
        } else {
            throw new Error(data.error || 'Upload failed');
        }
    })
    .catch(error => {
        console.error('Upload error:', error);
        MMCLoader.updateText('Upload Failed', error.message);
        MMCLoader.hide(3000);
    });
}

// ============================================================================
// EXAMPLE 3: Database Query / Data Loading
// ============================================================================
function loadPatientDataWithLoader(patientId) {
    MMCLoader.show('Loading Patient Data', 'Fetching medical records...');
    
    fetch(`/api/patients/${patientId}`)
    .then(response => response.json())
    .then(data => {
        MMCLoader.updateText('Loading Patient Data', 'Processing records...');
        
        // Simulate some processing time
        return new Promise(resolve => {
            setTimeout(() => resolve(data), 1000);
        });
    })
    .then(data => {
        MMCLoader.setStatus('complete');
        MMCLoader.setTitle('Data Loaded Successfully');
        
        setTimeout(() => {
            MMCLoader.hide(300);
            // Update UI with the data
            displayPatientData(data);
        }, 800);
    })
    .catch(error => {
        console.error('Error loading patient data:', error);
        MMCLoader.updateText('Error Loading Data', error.message);
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 4: Multi-Step Process (Complex Operation)
// ============================================================================
function processPatientCheckoutWithLoader(patientId) {
    const steps = [
        { title: 'Initializing Checkout', message: 'Step 1 of 4: Preparing...' },
        { title: 'Calculating Charges', message: 'Step 2 of 4: Computing invoice...' },
        { title: 'Processing Payment', message: 'Step 3 of 4: Processing transaction...' },
        { title: 'Finalizing Records', message: 'Step 4 of 4: Updating system...' }
    ];
    
    let currentStep = 0;
    
    function executeStep() {
        if (currentStep === 0) {
            MMCLoader.show(steps[0].title, steps[0].message);
        } else {
            MMCLoader.updateText(steps[currentStep].title, steps[currentStep].message);
        }
        
        // Simulate step processing (1.5 seconds per step)
        setTimeout(() => {
            currentStep++;
            if (currentStep < steps.length) {
                executeStep();
            } else {
                // All steps complete
                MMCLoader.setStatus('complete');
                MMCLoader.updateText('Checkout Complete', 'Receipt generated');
                
                setTimeout(() => {
                    MMCLoader.setStatus('done');
                    MMCLoader.hide(2000);
                    // Show receipt or redirect
                }, 800);
            }
        }, 1500);
    }
    
    executeStep();
}

// ============================================================================
// EXAMPLE 5: Drug Search/Autocomplete
// ============================================================================
function searchDrugsWithLoader(searchTerm) {
    if (!searchTerm) {
        MMCLoader.hide();
        return;
    }
    
    MMCLoader.show('Searching Drugs', `Looking for: ${searchTerm}`);
    
    fetch(`/api/drugs/search?q=${encodeURIComponent(searchTerm)}`)
    .then(response => response.json())
    .then(results => {
        MMCLoader.setStatus('complete');
        MMCLoader.updateText('Search Complete', `Found ${results.length} results`);
        
        setTimeout(() => {
            MMCLoader.hide(200);
            displaySearchResults(results);
        }, 600);
    })
    .catch(error => {
        console.error('Search error:', error);
        MMCLoader.updateText('Search Failed', 'Unable to search drugs');
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 6: Add to Cart Operation
// ============================================================================
function addDrugToCartWithLoader(drugId, drugName) {
    MMCLoader.show('Adding to Cart', `Adding ${drugName}...`);
    
    fetch('/api/cart/add', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('[name="csrf_token"]')?.value || ''
        },
        body: JSON.stringify({ drug_id: drugId, quantity: 1 })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            MMCLoader.setStatus('complete');
            MMCLoader.updateText('Added to Cart', `${drugName} added successfully`);
            
            setTimeout(() => {
                MMCLoader.setStatus('done');
                MMCLoader.hide(1500);
            }, 600);
        } else {
            throw new Error(data.error || 'Failed to add to cart');
        }
    })
    .catch(error => {
        console.error('Cart error:', error);
        MMCLoader.updateText('Error', error.message);
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 7: Email/Message Sending
// ============================================================================
function sendPrescriptionEmailWithLoader(prescriptionId, recipientEmail) {
    MMCLoader.show('Sending Email', `Sending to ${recipientEmail}...`);
    
    fetch('/api/prescriptions/send-email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('[name="csrf_token"]')?.value || ''
        },
        body: JSON.stringify({ 
            prescription_id: prescriptionId,
            recipient: recipientEmail 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            MMCLoader.setStatus('complete');
            MMCLoader.setTitle('Email Sent Successfully');
            
            setTimeout(() => {
                MMCLoader.setStatus('done');
                MMCLoader.hide(2000);
            }, 800);
        } else {
            throw new Error(data.error || 'Email sending failed');
        }
    })
    .catch(error => {
        console.error('Email error:', error);
        MMCLoader.updateText('Failed to Send Email', error.message);
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 8: Data Export/Generation
// ============================================================================
function generateInvoiceWithLoader(invoiceId) {
    MMCLoader.show('Generating Invoice', 'Processing financial data...');
    
    fetch(`/api/invoices/${invoiceId}/generate-pdf`, {
        method: 'POST'
    })
    .then(response => {
        if (response.ok) {
            MMCLoader.updateText('Generating Invoice', 'Creating PDF...');
            return response.blob();
        } else {
            throw new Error('Failed to generate invoice');
        }
    })
    .then(blob => {
        MMCLoader.setStatus('complete');
        MMCLoader.setTitle('Invoice Generated');
        
        setTimeout(() => {
            MMCLoader.setStatus('done');
            
            // Download the file
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `invoice-${invoiceId}.pdf`;
            link.click();
            
            MMCLoader.hide(1500);
        }, 600);
    })
    .catch(error => {
        console.error('Generation error:', error);
        MMCLoader.updateText('Generation Failed', error.message);
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 9: Form Validation Before Submit
// ============================================================================
function validateAndSubmitFormWithLoader() {
    const form = document.querySelector('#patient-form');
    
    // Start validation
    MMCLoader.show('Validating Form', 'Checking all fields...');
    
    // Simulate validation
    setTimeout(() => {
        const isValid = validateForm(form);
        
        if (isValid) {
            MMCLoader.updateText('Form Valid', 'All fields look good');
            MMCLoader.setStatus('complete');
            
            setTimeout(() => {
                MMCLoader.updateText('Submitting...', 'Sending to server');
                // Actually submit the form
                form.submit();
            }, 600);
        } else {
            MMCLoader.updateText('Validation Error', 'Please check the highlighted fields');
            MMCLoader.hide(2000);
            highlightInvalidFields(form);
        }
    }, 1000);
}

// ============================================================================
// EXAMPLE 10: Login/Authentication
// ============================================================================
function loginWithLoader(email, password) {
    MMCLoader.show('Signing In', 'Verifying credentials...');
    
    fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('[name="csrf_token"]')?.value || ''
        },
        body: JSON.stringify({ email, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            MMCLoader.setStatus('complete');
            MMCLoader.updateText('Login Successful', 'Redirecting to dashboard...');
            
            setTimeout(() => {
                MMCLoader.setStatus('done');
                // Redirect
                window.location.href = data.redirect_url || '/dashboard';
            }, 800);
        } else {
            throw new Error(data.message || 'Login failed');
        }
    })
    .catch(error => {
        console.error('Login error:', error);
        MMCLoader.updateText('Login Failed', error.message);
        MMCLoader.hide(2000);
    });
}

// ============================================================================
// EXAMPLE 11: Simple Quick Operation
// ============================================================================
function quickOperationWithAutoHide() {
    // Show loading
    MMCLoader.show('Processing', 'Please wait...');
    
    // Simulate quick operation (500ms)
    setTimeout(() => {
        MMCLoader.setStatus('complete', 1500); // Auto-hide after 1.5 seconds
    }, 500);
}

// ============================================================================
// EXAMPLE 12: Error Handling Pattern
// ============================================================================
function operationWithErrorHandlingWithLoader() {
    MMCLoader.show('Processing', 'Starting operation...');
    
    // Simulate some async operation
    Promise.resolve()
    .then(() => {
        MMCLoader.setTitle('Processing');
        MMCLoader.setMessage('Step 1 complete, continuing...');
        return performAsyncTask();
    })
    .then(result => {
        if (result.error) {
            throw new Error(result.error);
        }
        
        MMCLoader.setStatus('complete');
        MMCLoader.updateText('Success', 'Operation completed successfully');
        
        setTimeout(() => {
            MMCLoader.setStatus('done');
            MMCLoader.hide(2000);
        }, 800);
    })
    .catch(error => {
        console.error('Operation error:', error);
        
        // Show error state
        MMCLoader.updateText('Operation Failed', error.message);
        
        // Decide: auto-hide or keep showing for user to read
        MMCLoader.hide(3000); // Keep visible for 3 seconds
    });
}

// ============================================================================
// HELPER FUNCTIONS (Examples)
// ============================================================================

function validateForm(form) {
    // Your validation logic here
    return form.checkValidity();
}

function highlightInvalidFields(form) {
    // Your highlight logic here
}

function performAsyncTask() {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({ error: null, data: {} });
        }, 1500);
    });
}

function displaySearchResults(results) {
    // Your display logic here
}

function displayPatientData(data) {
    // Your display logic here
}

// ============================================================================
// USAGE IN HTML
// ============================================================================
/*

<!-- In your HTML form: -->
<form id="my-form" onsubmit="submitFormWithLoader(); return false;">
    <!-- Form fields -->
    <button type="submit">Submit</button>
</form>

<!-- On a button click: -->
<button onclick="addDrugToCartWithLoader(123, 'Aspirin')">Add to Cart</button>

<!-- On file upload: -->
<input type="file" onchange="uploadFileWithLoader(this.files[0])">

<!-- On patient selection: -->
<select onchange="loadPatientDataWithLoader(this.value)">
    <option value="">Select a patient...</option>
    <!-- Options -->
</select>

<!-- On search input: -->
<input type="text" 
       placeholder="Search drugs..." 
       oninput="searchDrugsWithLoader(this.value)">

<!-- On checkout button: -->
<button onclick="processPatientCheckoutWithLoader(123)">Checkout</button>

*/
