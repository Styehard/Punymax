// Saves options to chrome.storage
function save_options() {
  var languague = document.getElementById('languague').value;
  var detail = document.getElementById('detail').value;
  var level = document.getElementById('level').value;
  chrome.storage.sync.set({
    userLanguague: languague,
    userDetail: detail,
    userLevel: level,
  }, function() {
    // Update status to let user know options were saved.
    var status = document.getElementById('status');
    status.textContent = 'Options saved.';
    setTimeout(function() {
      status.textContent = '';
    }, 750);
  });
}

// Uopdates options from chrome.storage
function restore_options() {
  chrome.storage.sync.get({
    userLanguague: 'es',
    userDetail: 'small',
    userLevel: 0
  }, function(items) {
    document.getElementById('languague').value = items.userLanguague;
    document.getElementById('detail').value = items.userDetail;
    document.getElementById('level').value = items.userLevel;

  });
}
document.addEventListener('DOMContentLoaded', restore_options);
document.getElementById('save').addEventListener('click',
    save_options);