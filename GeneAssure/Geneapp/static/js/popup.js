document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('uploadForm').addEventListener('submit', function(event) {
        var fastq1 = document.getElementsByName('fastq1')[0];
        var fastq2 = document.getElementsByName('fastq2')[0];

        if (!fastq1.files.length || !fastq2.files.length) {
            alert('Please select both FastQ1 and FastQ2 files.');
            event.preventDefault(); // Prevent the form from submitting
        }
    });
});