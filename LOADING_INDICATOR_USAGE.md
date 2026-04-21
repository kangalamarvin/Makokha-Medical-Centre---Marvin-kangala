# MMC Loading Indicator System

## Overview
The Makokha Medical Centre system now includes a comprehensive loading indicator that works across all pages. It displays in the center of the screen with a semi-transparent backdrop and supports multiple states: **loading**, **complete**, and **done**.

## Features
✅ Global availability on all pages (base.html inheritance)  
✅ Multiple status states with distinct visual indicators  
✅ Smooth animations and transitions  
✅ Mobile-responsive design  
✅ Automatic and manual control  
✅ Auto-hide functionality with customizable delays  

## Basic Usage

### Show Loading State
```javascript
// Simple loading
MMCLoader.show();

// With custom title
MMCLoader.show('Uploading File...');

// With title and message
MMCLoader.show('Processing Data', 'Please wait while we process your request');
```

### Update Text While Loading
```javascript
// Update just the title
MMCLoader.setTitle('Validating...');

// Update just the message
MMCLoader.setMessage('Step 1 of 3 complete');

// Update both
MMCLoader.updateText('Processing...', 'Nearly done');
```

### Change Status States
```javascript
// Show loading spinner (default state)
MMCLoader.setStatus('loading');

// Show green checkmark (completion)
MMCLoader.setStatus('complete');

// Show cyan checkmark (done/final state)
MMCLoader.setStatus('done');

// Set status and auto-hide after 2 seconds
MMCLoader.setStatus('complete', 2000);
MMCLoader.setStatus('done', 3000);
```

### Hide the Loading Indicator
```javascript
// Hide immediately
MMCLoader.hide();

// Hide with 300ms fade-out delay
MMCLoader.hide(300);

// Hide with 500ms delay
MMCLoader.hide(500);
```

## Status States

| State | Icon | Color | Use Case |
|-------|------|-------|----------|
| `loading` | Spinning circle | Blue (#0d6efd) | Operation in progress |
| `complete` | ✓ Checkmark | Green (#28a745) | Operation succeeded, intermediate step |
| `done` | ✓ Checkmark | Cyan (#17a2b8) | Final completion, ready to close |

## Common Scenarios

### Scenario 1: File Upload
```javascript
MMCLoader.show('Uploading File...', 'Preparing file...');

// After upload completes
MMCLoader.setStatus('complete');
MMCLoader.setMessage('Upload successful');

// Show final state and auto-hide
setTimeout(() => {
    MMCLoader.setStatus('done');
    MMCLoader.hide(2000); // Hide after 2 seconds
}, 1000);
```

### Scenario 2: Form Submission
```javascript
MMCLoader.show('Submitting Form...', 'Please wait');

fetch('/api/submit-form', {
    method: 'POST',
    body: formData
})
.then(response => {
    MMCLoader.setStatus('complete');
    MMCLoader.setTitle('Submitted Successfully');
    return response.json();
})
.catch(error => {
    MMCLoader.setTitle('Error');
    MMCLoader.setMessage(error.message);
    MMCLoader.hide(2000);
})
.finally(() => {
    // Optional: auto-hide after success
    setTimeout(() => MMCLoader.hide(), 2000);
});
```

### Scenario 3: Multi-Step Process
```javascript
MMCLoader.show('Processing...', 'Step 1: Validating data');

setTimeout(() => {
    MMCLoader.updateText('Processing...', 'Step 2: Saving to database');
}, 2000);

setTimeout(() => {
    MMCLoader.updateText('Processing...', 'Step 3: Sending notifications');
}, 4000);

setTimeout(() => {
    MMCLoader.setStatus('complete');
    MMCLoader.setTitle('All Steps Complete');
}, 6000);

setTimeout(() => {
    MMCLoader.setStatus('done');
    MMCLoader.hide(2000);
}, 8000);
```

### Scenario 4: Auto-Sequence
```javascript
// Automatically runs: loading → complete → done → hide
MMCLoader.executeSequence('Processing Request', 'Please wait...');
// Hides after ~4 seconds
```

## API Reference

### Methods

#### `show(title, message)`
Display the loading overlay.
- `title` (string): Main title text (default: "Loading...")
- `message` (string): Subtitle message (optional, default: "")

#### `hide(delay)`
Hide the loading overlay.
- `delay` (number): Milliseconds to wait before hiding (default: 0)

#### `setTitle(title)`
Update only the title text.
- `title` (string): New title text

#### `setMessage(message)`
Update only the message text.
- `message` (string): New message text

#### `updateText(title, message)`
Update both title and message.
- `title` (string): New title text
- `message` (string): New message text (optional)

#### `setStatus(state, autoHideAfter)`
Change the loading state.
- `state` (string): One of `'loading'`, `'complete'`, `'done'`
- `autoHideAfter` (number): Auto-hide after N milliseconds (optional)

#### `executeSequence(title, message)`
Run automatic loading → complete → done → hide sequence.
- `title` (string): Title for loading state (default: "Processing...")
- `message` (string): Message for loading state (optional)

#### `getStatus()`
Get current loader status (for debugging).
Returns object with: `{ isVisible, currentState, title, message }`

### Constants

```javascript
// Available states
MMCLoader.STATES.LOADING   // 'loading'
MMCLoader.STATES.COMPLETE  // 'complete'
MMCLoader.STATES.DONE      // 'done'
```

## Styling Customization

The loader uses CSS custom properties that can be overridden:

```css
/* Override colors in your CSS */
:root {
    --loader-primary-color: #0d6efd;   /* Loading spinner color */
    --loader-success-color: #28a745;   /* Complete checkmark color */
    --loader-info-color: #17a2b8;      /* Done checkmark color */
}
```

## Browser Support
- Chrome 60+
- Firefox 55+
- Safari 12+
- Edge 79+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Notes
- The loader is available globally on all pages (loaded in base.html)
- It works with both authenticated and unauthenticated pages
- The backdrop blur effect requires modern browsers (gracefully degrades to semi-transparent background)
- The loader automatically prevents multiple simultaneous instances
- All animations are GPU-accelerated for smooth performance

## Troubleshooting

### Loader Not Showing
1. Check browser console for errors
2. Verify `loading.js` is included in base.html
3. Ensure JavaScript is enabled in browser

### Loader Not Hiding
```javascript
// Force hide with any pending animations
MMCLoader.hide(0);
```

### Check Current Status
```javascript
console.log(MMCLoader.getStatus());
```

## Examples in Base Templates

The loader is available on all pages that inherit from base.html:
- Authentication pages (login, password reset)
- Dashboard pages (admin, doctor, pharmacist)
- All role-specific pages

Just call `MMCLoader.show()` and related methods directly in any page script.
