// login.js

document.getElementById('login-form').addEventListener('submit', function (event) {
    // Prevent the default form submission behavior
    event.preventDefault();

    // Show the loading spinner and hide the login button
    document.getElementById('loading-spinner').classList.remove('d-none');
    document.querySelector('.btn-login').classList.add('d-none');

    // Submit the form after a short delay (for demonstration purposes)
    setTimeout(function () {
        document.getElementById('login-form').submit();
    }, 1000); // Adjust the delay as needed or remove it if you don't want a delay
});