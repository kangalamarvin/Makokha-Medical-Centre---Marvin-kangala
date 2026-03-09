// Password toggle functionality
function togglePassword() {
    const passwordField = document.getElementById('password');
    const toggleIcon = document.querySelector('.toggle-password i');
    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        toggleIcon.classList.remove('fa-eye');
        toggleIcon.classList.add('fa-eye-slash');
    } else {
        passwordField.type = 'password';
        toggleIcon.classList.remove('fa-eye-slash');
        toggleIcon.classList.add('fa-eye');
    }
}

// Cart functionality for pharmacist
let cartItems = [];

function escapeHtml(value) {
    const s = String(value ?? '');
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function addToCart(drugId, drugName, price, quantity = 1, dosage = '', prescriptionItemId = null) {
    // Check if item already in cart
    const existingItem = cartItems.find(item => item.drugId === drugId && item.dosage === dosage);
    
    if (existingItem) {
        // Update quantity
        existingItem.quantity += quantity;
        updateCartItem(existingItem);
    } else {
        // Add new item
        const newItem = {
            id: Date.now(),
            drugId,
            drugName,
            price,
            quantity,
            dosage,
            prescriptionItemId
        };
        cartItems.push(newItem);
        renderCartItem(newItem);
    }
    
    updateCartTotal();
    saveCart();
}

function removeFromCart(itemId) {
    cartItems = cartItems.filter(item => item.id !== itemId);
    document.querySelector(`.cart-item[data-id="${itemId}"]`).remove();
    updateCartTotal();
    saveCart();
}

function updateCartItem(item) {
    const cartItemElement = document.querySelector(`.cart-item[data-id="${item.id}"]`);
    if (cartItemElement) {
        cartItemElement.querySelector('.quantity-value').textContent = item.quantity;
        cartItemElement.querySelector('.item-total').textContent = `$${(item.price * item.quantity).toFixed(2)}`;
    }
}

function renderCartItem(item) {
    const cartItemsContainer = document.getElementById('cartItems');
    
    // Remove empty cart message if it exists
    const emptyCart = cartItemsContainer.querySelector('.empty-cart');
    if (emptyCart) {
        emptyCart.remove();
    }
    
    // Create cart item element
    const cartItemElement = document.createElement('div');
    cartItemElement.className = 'cart-item';
    cartItemElement.dataset.id = item.id;
    
    cartItemElement.innerHTML = `
        <div class="cart-item-info">
            <h5>${escapeHtml(item.drugName)}</h5>
            ${item.dosage ? `<p>Dosage: ${escapeHtml(item.dosage)}</p>` : ''}
            <p>Price: $${item.price.toFixed(2)}</p>
        </div>
        <div class="cart-item-actions">
            <div class="cart-item-quantity">
                <button class="decrement-btn" onclick="updateQuantity(${item.id}, -1)">-</button>
                <span class="quantity-value">${item.quantity}</span>
                <button class="increment-btn" onclick="updateQuantity(${item.id}, 1)">+</button>
            </div>
            <div class="item-total">$${(item.price * item.quantity).toFixed(2)}</div>
            <i class="fas fa-trash cart-item-delete" onclick="removeFromCart(${item.id})"></i>
        </div>
    `;
    
    cartItemsContainer.appendChild(cartItemElement);
}

function updateQuantity(itemId, change) {
    const item = cartItems.find(item => item.id === itemId);
    if (item) {
        const newQuantity = item.quantity + change;
        if (newQuantity > 0) {
            item.quantity = newQuantity;
            updateCartItem(item);
            updateCartTotal();
            saveCart();
        } else {
            removeFromCart(itemId);
        }
    }
}

function updateCartTotal() {
    const total = cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    document.getElementById('cartTotal').textContent = `$${total.toFixed(2)}`;
}

function clearCart() {
    cartItems = [];
    document.getElementById('cartItems').innerHTML = `
        <div class="empty-cart">
            <i class="fas fa-cart-arrow-down"></i>
            <p>Your cart is empty</p>
        </div>
    `;
    document.getElementById('cartTotal').textContent = '$0.00';
    saveCart();
}

function saveCart() {
    localStorage.setItem('pharmacyCart', JSON.stringify(cartItems));
}

function loadCart() {
    const savedCart = localStorage.getItem('pharmacyCart');
    if (savedCart) {
        cartItems = JSON.parse(savedCart);
        cartItems.forEach(item => renderCartItem(item));
        updateCartTotal();
    }
}

function getCartItems() {
    return cartItems;
}

// Initialize cart when page loads
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('cartItems')) {
        loadCart();
    }
});

// Form navigation for doctor's patient form
function nextSection(currentId, nextId) {
    document.getElementById(currentId).classList.remove('active');
    document.getElementById(nextId).classList.add('active');
}

function prevSection(currentId, prevId) {
    document.getElementById(currentId).classList.remove('active');
    document.getElementById(prevId).classList.add('active');
}

// Modal functionality
function openModal(modalId) {
    document.getElementById(modalId).classList.add('show');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('show');
}

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.classList.remove('show');
    }
});

// Toggle sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('collapsed');
}

// DataTable initialization
function initializeDataTable(tableId, options = {}) {
    const table = document.getElementById(tableId);
    if (table) {
        $(table).DataTable({
            responsive: true,
            dom: '<"top"lf>rt<"bottom"ip>',
            pageLength: 25,
            ...options
        });
    }
}

// Initialize all DataTables on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeDataTable('drugsTable');
    initializeDataTable('salesTable');
    initializeDataTable('inventoryTable');
    initializeDataTable('prescriptionsTable');
});

// AJAX error handling
$(document).ajaxError(function(event, jqxhr, settings, thrownError) {
    console.error('AJAX Error:', settings.url, thrownError);
    alert('An error occurred. Please try again.');
});

// Flash message auto-close
setTimeout(function() {
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        message.style.transition = 'opacity 0.5s ease';
        message.style.opacity = '0';
        setTimeout(() => message.remove(), 500);
    });
}, 5000);