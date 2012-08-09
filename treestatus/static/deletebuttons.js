function deleteUser(user) {
  var f = document.getElementById('deleteForm');
  var input = document.createElement('input');  
  input.setAttribute('type', 'submit');
  input.setAttribute('value', 'Delete');
  input.setAttribute('name', user);
  input.setAttribute('form', 'deleteForm');
  f.appendChild(input);
  input.click();
}


function onDeleteButtonClick(e) {
  var id = e.target.id;
  if (id.indexOf('delete:') != 0)
    return;

  e.preventDefault();
  var elems = document.getElementsByTagName('button');
  for (var i = 0; i < elems.length; i++) {
    elems[i].removeEventListener('click', onDeleteButtonClick);
  }

  deleteUser(id);
}


function onLoad() {
  document.removeEventListener('DOMContentLoaded', onLoad);

  var elems = document.getElementsByTagName("button");
  for (var i = 0; i < elems.length; i++) {
    elems[i].addEventListener('click', onDeleteButtonClick);
  }
}


document.addEventListener('DOMContentLoaded', onLoad, 'false');
