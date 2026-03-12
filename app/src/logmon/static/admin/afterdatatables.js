var iteminprogress;
var hasoptions = ['checkbox', 'radio', 'select2'];


function afterdatatables() {
    console.log('afterdatatables()');

    // always make sure embedded links in input field open in a new tab
    editor.on('opened', function(e, type){
        $('.DTE_Field_Input a').attr('target', '_blank');
    });

    // special processing for task checklist
    var pathname = location.pathname;

    // handle special processing for /xyz here
    if (pathname === '/xyz') {

    // special processing for /abc
    } else if (pathname === '/abc') {

    }
}
