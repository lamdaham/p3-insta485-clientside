document.addEventListener('DOMContentLoaded', () => {
    // Select all toggle-like buttons
    const toggleButtons = document.querySelectorAll('.toggle-like-button');

    toggleButtons.forEach(button => {
        button.addEventListener('click', function() {
            const form = this.closest('form');
            const operationField = form.querySelector('.operation-field');
            const postId = form.querySelector('input[name="postid"]').value;

            // Toggle the operation value and button label
            if (operationField.value === 'like') {
                operationField.value = 'unlike';
                operationField.name = 'unlike';
                this.value = 'Unlike';
            } else {
                operationField.value = 'like';
                operationField.name = 'like';
                this.value = 'Like';
            }

            // Optionally, submit the form automatically after toggling
            // form.submit();
        });
    });
});