// Pharmacist Dashboard Functions

// XSS Protection: Escape HTML special characters
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

$(document).ready(function() {
    // Load drugs for dispensing
    function loadDrugs() {
        $('#pharmaDrugList').html('<div class="loading-spinner"><i class="fas fa-spinner fa-spin"></i> Loading drugs...</div>');
        
        $.get('/api/drugs', function(data) {
            // Check if data is actually an array (not HTML from redirect)
            if (!Array.isArray(data)) {
                console.error('Expected array but got:', typeof data);
                $('#pharmaDrugList').html('<div class="error-loading"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</div>');
                return;
            }
            
            if (data.length > 0) {
                let html = '';
                data.forEach(function(drug) {
                    // Properly escape drug name for use in HTML and JavaScript
                    const drugName = escapeHtml(drug.name);
                    const drugSpec = escapeHtml(drug.specification || 'No specification');
                    
                    html += `
                        <div class="drug-card" data-id="${drug.id}">
                            <div class="drug-info">
                                <h5>${drugName}</h5>
                                <p>${drugSpec}</p>
                                <div class="drug-meta">
                                    <span class="price">$${parseFloat(drug.selling_price).toFixed(2)}</span>
                                    <span class="stock">${parseInt(drug.remaining_quantity)} in stock</span>
                                </div>
                            </div>
                            <div class="drug-actions">
                                <button class="btn btn-sm btn-add-to-cart" data-drug-id="${drug.id}" data-drug-name="${drugName}" data-drug-price="${drug.selling_price}">
                                    <i class="fas fa-cart-plus"></i> Add
                                </button>
                            </div>
                        </div>
                    `;
                });
                $('#pharmaDrugList').html(html);
                
                // Add click handlers after inserting HTML
                $('.btn-add-to-cart').on('click', function() {
                    const drugId = $(this).data('drug-id');
                    const drugName = $(this).data('drug-name');
                    const drugPrice = $(this).data('drug-price');
                    addToCart(drugId, drugName, drugPrice);
                });
            } else {
                $('#pharmaDrugList').html('<div class="empty-list"><i class="fas fa-box-open"></i> No drugs available</div>');
            }
        }).fail(function(jqXHR, textStatus, errorThrown) {
            console.error('Failed to load drugs:', textStatus, errorThrown);
            if (jqXHR.status === 302 || jqXHR.status === 401) {
                $('#pharmaDrugList').html('<div class="error-loading"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</div>');
            } else {
                $('#pharmaDrugList').html('<div class="error-loading"><i class="fas fa-exclamation-circle"></i> Failed to load drugs. Please refresh the page.</div>');
            }
        });
    }
    
    // Load sales
    function loadSales() {
        $('#salesTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading sales...</td></tr>');
        
        $.get('/pharmacist/sales', function(data) {
            if (!Array.isArray(data)) {
                console.error('Expected array but got:', typeof data);
                $('#salesTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (data.length > 0) {
                let html = '';
                data.forEach(function(sale) {
                    html += `
                        <tr>
                            <td>${sale.sale_number}</td>
                            <td>${sale.created_at}</td>
                            <td>${sale.patient_name || 'Walk-in'}</td>
                            <td>${sale.items_count}</td>
                            <td>$${sale.total_amount.toFixed(2)}</td>
                            <td>
                                <button class="btn btn-sm btn-view-receipt" data-id="${sale.id}">
                                    <i class="fas fa-receipt"></i> Receipt
                                </button>
                            </td>
                        </tr>
                    `;
                });
                $('#salesTable tbody').html(html);
            } else {
                $('#salesTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-info-circle"></i> No sales found</td></tr>');
            }
        });
    }
    
    // Load inventory
    function loadInventory() {
        $('#inventoryTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading inventory...</td></tr>');
        
        $.get('/api/drugs?limit=100', function(data) {
            if (!Array.isArray(data)) {
                console.error('Expected array but got:', typeof data);
                $('#inventoryTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (data.length > 0) {
                let html = '';
                data.forEach(function(drug) {
                    let statusClass = '';
                    let statusText = '';
                    
                    if (drug.remaining_quantity === 0) {
                        statusClass = 'out-of-stock';
                        statusText = 'Out of Stock';
                    } else if (drug.remaining_quantity < 10) {
                        statusClass = 'low-stock';
                        statusText = 'Low Stock';
                    } else {
                        statusClass = 'in-stock';
                        statusText = 'In Stock';
                    }
                    
                    html += `
                        <tr>
                            <td>${drug.drug_number}</td>
                            <td>${drug.name}</td>
                            <td>${drug.specification || '-'}</td>
                            <td>$${drug.selling_price.toFixed(2)}</td>
                            <td>${drug.remaining_quantity}</td>
                            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                        </tr>
                    `;
                });
                $('#inventoryTable tbody').html(html);
            } else {
                $('#inventoryTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-info-circle"></i> No inventory found</td></tr>');
            }
        });
    }
    
    // Load prescriptions
    function loadPrescriptions() {
        $('#prescriptionsTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading prescriptions...</td></tr>');
        
        $.get('/pharmacist/prescriptions', function(data) {
            if (!Array.isArray(data)) {
                console.error('Expected array but got:', typeof data);
                $('#prescriptionsTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (data.length > 0) {
                let html = '';
                data.forEach(function(prescription) {
                    html += `
                        <tr>
                            <td>PR-${prescription.id.toString().padStart(4, '0')}</td>
                            <td>${prescription.patient_number} - ${prescription.patient_name}</td>
                            <td>Dr. ${prescription.doctor_name}</td>
                            <td>${prescription.created_at}</td>
                            <td>${prescription.items_count} items</td>
                            <td>
                                <button class="btn btn-sm btn-primary btn-dispense-prescription" data-id="${prescription.id}">
                                    <i class="fas fa-pills"></i> Dispense
                                </button>
                            </td>
                        </tr>
                    `;
                });
                $('#prescriptionsTable tbody').html(html);
            } else {
                $('#prescriptionsTable tbody').html('<tr><td colspan="6" class="text-center"><i class="fas fa-info-circle"></i> No pending prescriptions</td></tr>');
            }
        });
    }
    
    // View prescriptions button
    $('#viewPrescriptionsBtn').click(function() {
        loadPrescriptions();
        $('#prescriptionsModal').modal('show');
    });
    
    // Dispense prescription button
    $(document).on('click', '.btn-dispense-prescription', function() {
        const prescriptionId = $(this).data('id');
        
        $.get(`/pharmacist/prescription/${prescriptionId}`, function(data) {
            if (data && data.items && Array.isArray(data.items) && data.items.length > 0) {
                // Clear cart first
                clearCart();
                
                // Add prescription items to cart
                data.items.forEach(function(item) {
                    addToCart(item.drug_id, item.drug_name, item.unit_price, item.quantity, item.dosage);
                });
                
                // Show dispense button
                $('#dispensePrescriptionBtn').data('prescription-id', prescriptionId).show();
                $('#confirmSaleBtn').hide();
                
                $('#prescriptionsModal').modal('hide');
            }
        });
    });
    
    // Dispense prescription
    $('#dispensePrescriptionBtn').click(function() {
        const prescriptionId = $(this).data('prescription-id');
        const cartItems = getCartItems();
        
        if (cartItems.length === 0) {
            alert('Cart is empty');
            return;
        }
        
        const itemsData = cartItems.map(item => ({
            item_id: item.prescriptionItemId,
            quantity: item.quantity
        }));
        
        $.ajax({
            url: '/pharmacist/dispense',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                prescription_id: prescriptionId,
                items: itemsData
            }),
            success: function(response) {
                if (response.success) {
                    alert('Prescription dispensed successfully. Please proceed to reception for billing.');
                    
                    // Clear cart
                    clearCart();
                    
                    // Reset buttons
                    $('#dispensePrescriptionBtn').hide();
                    $('#confirmSaleBtn').show();
                } else {
                    alert('Error: ' + (response.error || 'Failed to dispense prescription'));
                }
            },
            error: function(xhr) {
                alert('Error: ' + (xhr.responseJSON?.error || 'Failed to dispense prescription'));
            }
        });
    });
    
    // Confirm sale
    $('#confirmSaleBtn').click(function() {
        const cartItems = getCartItems();
        
        if (cartItems.length === 0) {
            alert('Cart is empty');
            return;
        }
        
        // In a real app, you would collect patient info and payment method
        // For this example, we'll just process as a walk-in sale with cash payment
        
        const saleData = {
            items: cartItems.map(item => ({
                drug_id: item.drugId,
                description: item.drugName,
                quantity: item.quantity,
                unit_price: item.price
            })),
            payment_method: 'cash'
        };
        
        $.ajax({
            url: '/pharmacist/sale',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(saleData),
            success: function(response) {
                if (response.success) {
                    // Show receipt
                    showReceipt(response.sale_id);
                    
                    // Clear cart
                    clearCart();
                } else {
                    alert('Error: ' + (response.error || 'Failed to process sale'));
                }
            },
            error: function(xhr) {
                alert('Error: ' + (xhr.responseJSON?.error || 'Failed to process sale'));
            }
        });
    });
    
    // Show receipt
    function showReceipt(saleId) {
        $('#receiptContent').html('<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading receipt...</div>');
        
        $.get(`/pharmacist/sale/${saleId}/receipt`, function(data) {
            $('#receiptContent').html(data);
            $('#receiptModal').modal('show');
        });
    }
    
    // Print receipt
    $('#printReceiptBtn').click(function() {
        const printContent = $('#receiptContent').html();
        const originalContent = $('body').html();
        
        $('body').html(printContent);
        window.print();
        $('body').html(originalContent);
    });
    
    // Search sale for refund
    $('#searchSaleBtn').click(function() {
        const saleNumber = $('#refundSaleNumber').val().trim();
        
        if (!saleNumber) {
            alert('Please enter a sale number');
            return;
        }
        
        $.get(`/api/sales/${saleNumber}`, function(sale) {
            if (sale && sale.items && Array.isArray(sale.items)) {
                $('#refundSaleNo').text(sale.sale_number);
                $('#refundSaleDate').text(sale.created_at);
                $('#refundPatient').text(sale.patient_name || 'Walk-in');
                $('#refundTotal').text('$' + sale.total_amount.toFixed(2));
                
                // Load items
                let html = '';
                sale.items.forEach(function(item) {
                    html += `
                        <tr>
                            <td>${item.description}</td>
                            <td>$${item.unit_price.toFixed(2)}</td>
                            <td>${item.quantity}</td>
                            <td>$${item.total_price.toFixed(2)}</td>
                            <td>
                                <button class="btn btn-sm btn-select-refund" data-id="${item.id}">
                                    <i class="fas fa-undo"></i> Refund
                                </button>
                            </td>
                        </tr>
                    `;
                });
                $('#refundItemsList').html(html);
                
                $('#refundResults').show();
            } else {
                alert('Sale not found');
            }
        }).fail(function() {
            alert('Error searching for sale');
        });
    });
    
    // Process refund
    $('#processRefundBtn').click(function() {
        const saleNumber = $('#refundSaleNo').text();
        const selectedItems = $('.btn-select-refund.selected').map(function() {
            return $(this).data('id');
        }).get();
        
        if (selectedItems.length === 0) {
            alert('Please select items to refund');
            return;
        }
        
        if (!confirm(`Are you sure you want to refund ${selectedItems.length} items from sale ${saleNumber}?`)) {
            return;
        }
        
        $.ajax({
            url: '/pharmacist/refund',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                sale_number: saleNumber,
                items: selectedItems
            }),
            success: function(response) {
                if (response.success) {
                    alert('Refund processed successfully');
                    $('#refundResults').hide();
                    $('#refundSaleNumber').val('');
                } else {
                    alert('Error: ' + (response.error || 'Failed to process refund'));
                }
            },
            error: function(xhr) {
                alert('Error: ' + (xhr.responseJSON?.error || 'Failed to process refund'));
            }
        });
    });
    
    // Select items for refund
    $(document).on('click', '.btn-select-refund', function() {
        $(this).toggleClass('selected');
        
        const anySelected = $('.btn-select-refund.selected').length > 0;
        $('#processRefundBtn').prop('disabled', !anySelected);
    });
    
    // Refresh buttons
    $('#refreshSalesBtn').click(function() {
        loadSales();
    });
    
    $('#refreshInventoryBtn').click(function() {
        loadInventory();
    });
    
    // Initial load
    loadDrugs();
});

// Doctor Dashboard Functions
$(document).ready(function() {
    // Generate patient number based on type
    $('#patientType').change(function() {
        const patientType = $(this).val();
        $('#patientNumber').val(generatePatientNumber(patientType));
    });
    
    function generatePatientNumber(patientType) {
        // In a real app, this would make an AJAX call to get the next number
        // For demo purposes, we'll just generate a random number
        const prefix = patientType === 'OP' ? 'OPMNC' : 'IPMNC';
        const randomNum = Math.floor(100 + Math.random() * 900);
        return prefix + randomNum;
    }
    
    // Form navigation
    $('.btn-next').click(function() {
        const currentSection = $(this).closest('.form-section');
        const nextSectionId = $(this).data('next');
        currentSection.removeClass('active');
        $(`#${nextSectionId}`).addClass('active');
    });
    
    $('.btn-prev').click(function() {
        const currentSection = $(this).closest('.form-section');
        const prevSectionId = $(this).data('prev');
        currentSection.removeClass('active');
        $(`#${prevSectionId}`).addClass('active');
    });
    
    // Toggle gynecological history based on gender
    $('#gender').change(function() {
        const gender = $(this).val();
        if (gender === 'female') {
            $('#gynecologicalSection').show();
            $('#obstetricSection').show();
        } else {
            $('#gynecologicalSection').hide();
            $('#obstetricSection').hide();
        }
    });
    
    // Add lab test
    $('#addLabTestBtn').click(function() {
        const testId = $('#labTestSelect').val();
        const test = $('#labTestSelect option:selected').text();
        const results = $('#labTestResults').val();
        const comments = $('#labTestComments').val();
        
        if (!testId || !results) {
            alert('Please select a test and enter results');
            return;
        }
        
        // Add to lab tests table
        $('#labTestsTable tbody').append(`
            <tr data-test-id="${testId}">
                <td>${test}</td>
                <td>${results}</td>
                <td>${comments || '-'}</td>
                <td>
                    <button class="btn btn-sm btn-danger btn-remove-lab">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `);
        
        // Clear form
        $('#labTestSelect').val('');
        $('#labTestResults').val('');
        $('#labTestComments').val('');
    });
    
    // Remove lab test
    $(document).on('click', '.btn-remove-lab', function() {
        $(this).closest('tr').remove();
    });
    
    // Add prescription
    $('#addPrescriptionBtn').click(function() {
        const drugId = $('#prescriptionDrugSelect').val();
        const drug = $('#prescriptionDrugSelect option:selected').text();
        const dosage = $('#prescriptionDosage').val();
        const frequency = $('#prescriptionFrequency').val();
        const duration = $('#prescriptionDuration').val();
        const notes = $('#prescriptionNotes').val();
        
        if (!drugId || !dosage || !frequency || !duration) {
            alert('Please fill all required fields');
            return;
        }
        
        // Add to prescriptions table
        $('#prescriptionsTable tbody').append(`
            <tr data-drug-id="${drugId}">
                <td>${drug}</td>
                <td>${dosage}</td>
                <td>${frequency}</td>
                <td>${duration}</td>
                <td>${notes || '-'}</td>
                <td>
                    <button class="btn btn-sm btn-danger btn-remove-prescription">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `);
        
        // Clear form
        $('#prescriptionDrugSelect').val('');
        $('#prescriptionDosage').val('');
        $('#prescriptionFrequency').val('');
        $('#prescriptionDuration').val('');
        $('#prescriptionNotes').val('');
    });
    
    // Remove prescription
    $(document).on('click', '.btn-remove-prescription', function() {
        $(this).closest('tr').remove();
    });
    
    // Submit patient form
    $('#patientForm').submit(function(e) {
        e.preventDefault();
        
        // Collect form data
        const formData = {
            bioData: {
                patientType: $('#patientType').val(),
                patientNumber: $('#patientNumber').val(),
                name: $('#name').val(),
                age: $('#age').val(),
                gender: $('#gender').val(),
                address: $('#address').val(),
                phone: $('#phone').val(),
                nokName: $('#nokName').val(),
                nokContact: $('#nokContact').val(),
                tca: $('#tca').val()
            },
            chiefComplaints: $('#chiefComplaints').val(),
            diagnosis: $('#diagnosis').val(),
            treatment: $('#treatment').val(),
            labTests: [],
            prescriptions: []
        };
        
        // Collect lab tests
        $('#labTestsTable tbody tr').each(function() {
            formData.labTests.push({
                testId: $(this).data('test-id'),
                results: $(this).find('td:eq(1)').text(),
                comments: $(this).find('td:eq(2)').text()
            });
        });
        
        // Collect prescriptions
        $('#prescriptionsTable tbody tr').each(function() {
            formData.prescriptions.push({
                drugId: $(this).data('drug-id'),
                dosage: $(this).find('td:eq(1)').text(),
                frequency: $(this).find('td:eq(2)').text(),
                duration: $(this).find('td:eq(3)').text(),
                notes: $(this).find('td:eq(4)').text()
            });
        });
        
        // Submit via AJAX
        $.ajax({
            url: '/doctor/patient',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(formData),
            success: function(response) {
                if (response.success) {
                    alert('Patient record saved successfully');
                    window.location.href = '/doctor/patients';
                } else {
                    alert('Error: ' + (response.error || 'Failed to save patient record'));
                }
            },
            error: function(xhr) {
                alert('Error: ' + (xhr.responseJSON?.error || 'Failed to save patient record'));
            }
        });
    });
});

// Receptionist Dashboard Functions
$(document).ready(function() {
    // Search patient
    $('#searchPatientBtn').click(function() {
        const searchTerm = $('#patientSearch').val().trim();
        
        if (!searchTerm) {
            alert('Please enter a search term');
            return;
        }
        
        $.get('/api/patients', { search: searchTerm }, function(patients) {
            if (!Array.isArray(patients)) {
                console.error('Expected array but got:', typeof patients);
                alert('Session expired. Please login again.');
                return;
            }
            if (patients.length > 0) {
                let html = '';
                patients.forEach(function(patient) {
                    html += `
                        <tr>
                            <td>${patient.op_number || patient.ip_number}</td>
                            <td>${patient.name}</td>
                            <td>${patient.age}</td>
                            <td>${patient.gender}</td>
                            <td>
                                <button class="btn btn-sm btn-primary btn-select-patient" data-id="${patient.id}">
                                    <i class="fas fa-check"></i> Select
                                </button>
                            </td>
                        </tr>
                    `;
                });
                $('#searchResults tbody').html(html);
            } else {
                $('#searchResults tbody').html('<tr><td colspan="5" class="text-center">No patients found</td></tr>');
            }
        });
    });
    
    // Select patient
    $(document).on('click', '.btn-select-patient', function() {
        const patientId = $(this).data('id');
        
        $.get(`/api/patients/${patientId}`, function(patient) {
            $('#patientId').val(patient.id);
            $('#patientName').text(patient.name);
            $('#patientNumber').text(patient.op_number || patient.ip_number);
            $('#patientAge').text(patient.age);
            $('#patientGender').text(patient.gender);
            
            // Load services and lab tests
            loadPatientServices(patient.id);
            loadPatientLabTests(patient.id);
            loadPatientPrescriptions(patient.id);
            
            // Show billing section
            $('#searchSection').hide();
            $('#billingSection').show();
        });
    });
    
    // Load patient services
    function loadPatientServices(patientId) {
        $('#servicesTable tbody').html('<tr><td colspan="4" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading services...</td></tr>');
        
        $.get(`/api/patients/${patientId}/services`, function(services) {
            if (!Array.isArray(services)) {
                console.error('Expected array but got:', typeof services);
                $('#servicesTable tbody').html('<tr><td colspan="4" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (services.length > 0) {
                let html = '';
                services.forEach(function(service) {
                    html += `
                        <tr data-service-id="${service.id}">
                            <td>${service.name}</td>
                            <td>$${service.price.toFixed(2)}</td>
                            <td>
                                <input type="checkbox" class="service-checkbox" checked>
                            </td>
                            <td>$${service.price.toFixed(2)}</td>
                        </tr>
                    `;
                });
                $('#servicesTable tbody').html(html);
            } else {
                $('#servicesTable tbody').html('<tr><td colspan="4" class="text-center">No services recorded</td></tr>');
            }
            calculateTotal();
        });
    }
    
    // Load patient lab tests
    function loadPatientLabTests(patientId) {
        $('#labTestsTable tbody').html('<tr><td colspan="4" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading lab tests...</td></tr>');
        
        $.get(`/api/patients/${patientId}/lab-tests`, function(tests) {
            if (!Array.isArray(tests)) {
                console.error('Expected array but got:', typeof tests);
                $('#labTestsTable tbody').html('<tr><td colspan="4" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (tests.length > 0) {
                let html = '';
                tests.forEach(function(test) {
                    html += `
                        <tr data-test-id="${test.id}">
                            <td>${test.name}</td>
                            <td>$${test.price.toFixed(2)}</td>
                            <td>
                                <input type="checkbox" class="lab-test-checkbox" checked>
                            </td>
                            <td>$${test.price.toFixed(2)}</td>
                        </tr>
                    `;
                });
                $('#labTestsTable tbody').html(html);
            } else {
                $('#labTestsTable tbody').html('<tr><td colspan="4" class="text-center">No lab tests recorded</td></tr>');
            }
            calculateTotal();
        });
    }
    
    // Load patient prescriptions
    function loadPatientPrescriptions(patientId) {
        $('#prescriptionsTable tbody').html('<tr><td colspan="5" class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading prescriptions...</td></tr>');
        
        $.get(`/api/patients/${patientId}/prescriptions`, function(prescriptions) {
            if (!Array.isArray(prescriptions)) {
                console.error('Expected array but got:', typeof prescriptions);
                $('#prescriptionsTable tbody').html('<tr><td colspan="5" class="text-center"><i class="fas fa-exclamation-circle"></i> Session expired. Please <a href="/auth/login">login</a> again.</td></tr>');
                return;
            }
            if (prescriptions.length > 0) {
                let html = '';
                prescriptions.forEach(function(prescription) {
                    html += `
                        <tr data-prescription-id="${prescription.id}">
                            <td>${prescription.drug_name}</td>
                            <td>${prescription.dosage}</td>
                            <td>${prescription.quantity}</td>
                            <td>$${prescription.price.toFixed(2)}</td>
                            <td>$${(prescription.price * prescription.quantity).toFixed(2)}</td>
                        </tr>
                    `;
                });
                $('#prescriptionsTable tbody').html(html);
            } else {
                $('#prescriptionsTable tbody').html('<tr><td colspan="5" class="text-center">No prescriptions recorded</td></tr>');
            }
            calculateTotal();
        });
    }
    
    // Calculate total bill
    function calculateTotal() {
        let total = 0;
        
        // Services total
        $('#servicesTable tbody tr').each(function() {
            if ($(this).find('.service-checkbox').is(':checked')) {
                total += parseFloat($(this).find('td:eq(3)').text().substring(1));
            }
        });
        
        // Lab tests total
        $('#labTestsTable tbody tr').each(function() {
            if ($(this).find('.lab-test-checkbox').is(':checked')) {
                total += parseFloat($(this).find('td:eq(3)').text().substring(1));
            }
        });
        
        // Prescriptions total
        $('#prescriptionsTable tbody tr').each(function() {
            total += parseFloat($(this).find('td:eq(4)').text().substring(1));
        });
        
        $('#totalAmount').text('$' + total.toFixed(2));
    }
    
    // Checkbox change events
    $(document).on('change', '.service-checkbox, .lab-test-checkbox', function() {
        const row = $(this).closest('tr');
        const price = parseFloat(row.find('td:eq(1)').text().substring(1));
        
        if ($(this).is(':checked')) {
            row.find('td:eq(3)').text('$' + price.toFixed(2));
        } else {
            row.find('td:eq(3)').text('$0.00');
        }
        
        calculateTotal();
    });
    
    // Generate bill
    $('#generateBillBtn').click(function() {
        const patientId = $('#patientId').val();
        const paymentMethod = $('#paymentMethod').val();
        
        if (!patientId) {
            alert('No patient selected');
            return;
        }
        
        // Collect selected services
        const services = [];
        $('#servicesTable tbody tr').each(function() {
            if ($(this).find('.service-checkbox').is(':checked')) {
                services.push({
                    service_id: $(this).data('service-id'),
                    price: parseFloat($(this).find('td:eq(1)').text().substring(1))
                });
            }
        });
        
        // Collect selected lab tests
        const labTests = [];
        $('#labTestsTable tbody tr').each(function() {
            if ($(this).find('.lab-test-checkbox').is(':checked')) {
                labTests.push({
                    test_id: $(this).data('test-id'),
                    price: parseFloat($(this).find('td:eq(1)').text().substring(1))
                });
            }
        });
        
        // Collect prescriptions
        const prescriptions = [];
        $('#prescriptionsTable tbody tr').each(function() {
            prescriptions.push({
                prescription_id: $(this).data('prescription-id'),
                price: parseFloat($(this).find('td:eq(3)').text().substring(1)),
                quantity: parseInt($(this).find('td:eq(2)').text())
            });
        });
        
        const totalAmount = parseFloat($('#totalAmount').text().substring(1));
        
        // Submit via AJAX
        $.ajax({
            url: '/receptionist/bill',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                patient_id: patientId,
                services: services,
                lab_tests: labTests,
                prescriptions: prescriptions,
                payment_method: paymentMethod,
                total_amount: totalAmount
            }),
            success: function(response) {
                if (response.success) {
                    // Show receipt
                    showReceipt(response.bill_id);
                    
                    // Reset form
                    $('#searchSection').show();
                    $('#billingSection').hide();
                    $('#patientSearch').val('');
                } else {
                    alert('Error: ' + (response.error || 'Failed to generate bill'));
                }
            },
            error: function(xhr) {
                alert('Error: ' + (xhr.responseJSON?.error || 'Failed to generate bill'));
            }
        });
    });
    
    // Show receipt
    function showReceipt(billId) {
        $('#receiptContent').html('<div class="text-center"><i class="fas fa-spinner fa-spin"></i> Loading receipt...</div>');
        
        $.get(`/receptionist/bill/${billId}/receipt`, function(data) {
            $('#receiptContent').html(data);
            $('#receiptModal').modal('show');
        });
    }
    
    // Print receipt
    $('#printReceiptBtn').click(function() {
        const printContent = $('#receiptContent').html();
        const originalContent = $('body').html();
        
        $('body').html(printContent);
        window.print();
        $('body').html(originalContent);
    });
    
    // Back to search
    $('#backToSearchBtn').click(function() {
        $('#searchSection').show();
        $('#billingSection').hide();
    });
});