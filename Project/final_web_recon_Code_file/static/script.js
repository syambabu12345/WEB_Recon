'use strict';

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Reveal elements on scroll
    const revealOnScroll = () => {
        const elements = document.querySelectorAll('.feature-card, .about-content, .contact-container');
        elements.forEach(element => {
            const elementTop = element.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;
            if (elementTop < windowHeight - 100) {
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }
        });
    };

    window.addEventListener('scroll', revealOnScroll);
    revealOnScroll(); // Initial check
    // Enhanced Mobile Navigation Toggle with Animation
    const navToggle = document.getElementById('navToggle');
    const navLinks = document.querySelector('.nav-links');
    const header = document.querySelector('header');

    navToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
        navToggle.classList.toggle('active');
        
        // Add slide animation to nav links
        const links = navLinks.querySelectorAll('a');
        links.forEach((link, index) => {
            if (link.style.animation) {
                link.style.animation = '';
            } else {
                link.style.animation = `slideIn 0.3s ease forwards ${index * 0.1}s`;
            }
        });
    });

    // Add scroll-triggered header shadow
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            header.style.boxShadow = 'var(--shadow)';
            header.style.background = 'rgba(255, 255, 255, 0.95)';
        } else {
            header.style.boxShadow = 'none';
            header.style.background = 'var(--white)';
        }
    });

    // Close mobile menu when clicking outside
    document.addEventListener('click', (e) => {
        if (!navToggle.contains(e.target) && !navLinks.contains(e.target)) {
            navLinks.classList.remove('active');
            navToggle.classList.remove('active');
        }
    });

    // Enhanced Image Upload and Preview with drag and drop
    const imageUpload = document.getElementById('imageUpload');
    const preview = document.getElementById('preview');
    const uploadDemo = document.querySelector('.upload-demo');

    // Drag and drop functionality
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadDemo.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        uploadDemo.addEventListener(eventName, () => {
            uploadDemo.classList.add('highlight');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        uploadDemo.addEventListener(eventName, () => {
            uploadDemo.classList.remove('highlight');
        });
    });

    uploadDemo.addEventListener('drop', handleDrop);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const file = dt.files[0];
        handleFile(file);
    }

    imageUpload.addEventListener('change', function(e) {
        const file = e.target.files[0];
        handleFile(file);
    });

    function handleFile(file) {
        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                preview.innerHTML = '';
                
                const img = document.createElement('img');
                img.src = e.target.result;
                img.style.maxWidth = '100%';
                img.style.maxHeight = '300px';
                img.style.borderRadius = '10px';
                img.style.opacity = '0';
                
                preview.appendChild(img);
                
                // Fade in animation
                setTimeout(() => {
                    img.style.transition = 'opacity 0.5s ease';
                    img.style.opacity = '1';
                }, 100);
                
                simulateDetection();
            };
            
            reader.readAsDataURL(file);
        } else {
            showNotification('Please upload an image file.', 'error');
            imageUpload.value = '';
        }
    }

    // Enhanced Contact Form Handling with better UX
    const contactForm = document.getElementById('contactForm');
    
    contactForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const message = document.getElementById('message').value;
        
        if (!name || !email || !message) {
            showNotification('Please fill in all fields.', 'error');
            return;
        }
        
        if (!isValidEmail(email)) {
            showNotification('Please enter a valid email address.', 'error');
            return;
        }
        
        const submitButton = contactForm.querySelector('.submit-button');
        submitButton.innerHTML = '<span class="spinner"></span> Sending...';
        submitButton.disabled = true;
        
        // Simulate API call
        setTimeout(() => {
            showNotification('Emergency alert sent successfully!', 'success');
            contactForm.reset();
            submitButton.innerHTML = 'Send Alert';
            submitButton.disabled = false;
        }, 1500);
    });

    // Add input animations
    const formInputs = document.querySelectorAll('.form-group input, .form-group textarea');
    formInputs.forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', () => {
            if (!input.value) {
                input.parentElement.classList.remove('focused');
            }
        });
    });
});

// Helper Functions
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Notification System
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateY(0)';
    }, 10);
    
    // Remove after delay
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateY(-20px)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

function simulateDetection() {
    const preview = document.getElementById('preview');
    
    // Add loading indicator with animation
    const loader = document.createElement('div');
    loader.className = 'detection-loader';
    loader.innerHTML = `
        <div class="loader-spinner"></div>
        <p class="loader-text">Processing image through ML pipeline...</p>
    `;
    preview.appendChild(loader);
    
    // Simulate ML pipeline steps
    const steps = [
        'Data preprocessing...',
        'Applying augmentation...',
        'Extracting features with ResNet50...',
        'Random Forest classification...'
    ];
    
    let currentStep = 0;
    const progressText = loader.querySelector('.loader-text');
    
    const processInterval = setInterval(() => {
        if (currentStep < steps.length) {
            progressText.textContent = steps[currentStep];
            currentStep++;
        } else {
            clearInterval(processInterval);
            setTimeout(() => {
                loader.remove();
                
                // Generate random detection result (for demo purposes)
                const isVictimDetected = Math.random() > 0.5;
                
                // Add detection result with animation
                const results = document.createElement('div');
                results.className = 'detection-results';
                results.style.opacity = '0';
                
                const resultClass = isVictimDetected ? 'detected' : 'not-detected';
                const resultIcon = isVictimDetected ? '⚠️' : '✓';
                const resultText = isVictimDetected ? 'Victim Detected' : 'No Victim Detected';
                const confidence = Math.floor(Math.random() * 20 + 80); // Random confidence between 80-99%
                
                results.innerHTML = `
                    <div class="result-box ${resultClass}">
                        <span class="result-icon">${resultIcon}</span>
                        <h4>${resultText}</h4>
                        <p>Confidence: ${confidence}%</p>
                    </div>
                `;
                
                preview.appendChild(results);
                
                // Fade in animation
                setTimeout(() => {
                    results.style.transition = 'opacity 0.5s ease';
                    results.style.opacity = '1';
                }, 100);
            }, 500);
        }
    }, 1000);
}

// Add smooth scroll for Learn More button
document.querySelector('.cta-button').addEventListener('click', (e) => {
    e.preventDefault();
    document.querySelector('#technical').scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });
});

// Smooth scrolling for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
            // Close mobile menu after clicking a link
            document.querySelector('.nav-links').classList.remove('active');
            document.getElementById('navToggle').classList.remove('active');
        }
    });
});
function startScan() {
    let domain = document.getElementById("domain").value;
    let options = {
        subdomainAnalysis: document.getElementById("subdomain").checked,
        sqlInjection: document.getElementById("sql").checked,
        xssTesting: document.getElementById("xss").checked,
        commandInjection: document.getElementById("cmd").checked,
    };

    if (!domain) {
        alert("Please enter a domain.");
        return;
    }

    document.getElementById("logs").value = "Starting scan...\n";

    fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, options })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("logs").value = data.logs;
    })
    .catch(error => {
        document.getElementById("logs").value = "Error: " + error;
    });
}

// Add scroll event listener for header
window.addEventListener('scroll', () => {
    const header = document.querySelector('header');
    if (window.scrollY > 50) {
        header.classList.add('scrolled');
    } else {
        header.classList.remove('scrolled');
    }
});

// Add error handling for image loading
window.addEventListener('error', function(e) {
    if (e.target.tagName === 'IMG') {
        e.target.src = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgZmlsbD0iI2VlZSIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBmb250LWZhbWlseT0iQXJpYWwiIGZvbnQtc2l6ZT0iMTQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuM2VtIiBmaWxsPSIjOTk5Ij5FcnJvcjwvdGV4dD48L3N2Zz4=';
    }
}, true);
