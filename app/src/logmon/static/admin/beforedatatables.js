$( function () {
    // if groups are being used, need to set up translation variables before datatables is initialized
    // required for datatables option {serverside:true}
    register_group_for_datatable('interest', '#metanav-select-interest');
});

// ckeditor default toolbar
// This represents the toolbar in #414
// copied from ckeditor build's sample.html
// built via https://ckeditor.com/ckeditor-5/online-builder/
ClassicEditor.defaultConfig = {
    toolbar: {
        items: [
            'heading',
            '|',
            'bold',
            'italic',
            'underline',
            'link',
            'bulletedList',
            'numberedList',
            'alignment',
            'strikethrough',
            'removeFormat',
            '|',
            'outdent',
            'indent',
            '|',
            'imageUpload',
            'blockQuote',
            'insertTable',
            'undo',
            'redo'
        ]
    },
    image: {
        toolbar: [
            'imageTextAlternative',
            'imageStyle:full',
            'imageStyle:side'
        ]
    },
    simpleUpload: {
        // The URL that the images are uploaded to, must match flask-reuploaded configuration
        uploadUrl: '/admin/uploads',

        // Enable the XMLHttpRequest.withCredentials property.
        withCredentials: true,

        // Headers sent along with the XMLHttpRequest to the upload server.
        headers: {
            'X-CSRF-TOKEN': 'CSRF-Token',
            Authorization: 'Bearer <JSON Web Token>'
        }
    },
    language: 'en',
    table: {
        contentToolbar: [
            'tableColumn',
            'tableRow',
            'mergeTableCells',
            'tableCellProperties',
            'tableProperties'
        ]
    },
    licenseKey: '',

}

function set_cell_status_class(row, data, displayNum, displayIndex, dataIndex) {
    // the keys for classes need to match the values in viewhelpers(.py).STATUS_DISPLAYORDER
    classes = {
        'overdue': 'status-overdue',
        'expires soon': 'status-expires-soon',
        'optional': 'status-optional',
        'up to date': 'status-up-to-date',
        'done': 'status-done',
    }
    // remove all status classes from indicated element
    for (var class_ in classes) {
        $('.status-field', row).removeClass(classes[class_]);
    }
    // add appropriate class based on data value
    $('.status-field', row).addClass(classes[data.status]);
}

function dismiss_button() {
    this.close();
}

function submit_button() {
    this.submit();
}

/**
 * show error message modal
 *
 * @param message - message to display
 */
function showerrorpopup(message) {
    var error = $('<div>');
    error.append(message);
    error.dialog({
        title: 'Error',
        modal: false,
        minWidth: 600,
        height: 'auto',
        buttons: {
            OK: function() {
                $(this).dialog('close');
            }
        }
    });
}

function render_month_date(data, type, row, meta) {
    if (data) {
        return data.slice(-5)
    } else {
        return data
    }
}
