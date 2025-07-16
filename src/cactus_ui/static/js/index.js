function formatRelativeDate(d) {
    // d: Date
    const now = new Date();
    const diff_ms = d - now;
    const diff_s = Math.floor(diff_ms / 1000);
    const diff_m = Math.floor(diff_s / 60);
    const diff_h = Math.floor(diff_m / 60);
    const diff_d = Math.floor(diff_h / 24);
    const formatter = new Intl.RelativeTimeFormat('en', {
        numeric: 'auto',
        style: 'short'
    });

    if (Math.abs(diff_s) < 120) {
        return formatter.format(diff_s, "second")
    } else if (Math.abs(diff_m) < 120) {
        return formatter.format(diff_m, "minute")
    } else if (Math.abs(diff_h) < 48) {
        return formatter.format(diff_h, "hour")
    } else {
        return formatter.format(diff_d, "day")
    }
}

function formatDate(d) {
    // d: Date
    return d.toLocaleString('sv'); // Sweden format is YYYY-MM-DD HH:MM:SS
}

function xhrRequest(uri, onSuccess, onFail) {
    // makes xhr request to uri. Calls onSuccess with xhr.responseText on success. 
    // Calls onFail otherwise with two params: xhr.status/null and xhr.responseText/null  
    const xhr = new XMLHttpRequest();
    xhr.open("GET", uri, true);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            if (xhr.status >= 200 && xhr.status <= 299) {
                onSuccess(xhr.responseText)
            } else {
                onFail(xhr.status, xhr.responseText)
            }
        }
    };
    xhr.onerror = function () {
        onFail(null, null)
    };
    xhr.send();
}