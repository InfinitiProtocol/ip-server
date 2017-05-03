var TablesDataTablesSources = {
	getDataSet: function (all) {
		var dataSet = [];
		if (all) {
			$.ajax('/ui/id/browse/0', {
				success: function(dataSet) {
					return dataSet;
				},
				error: function(){
					Index.createNotification('AJAX Failed.');
				},
   				type: 'GET'
			})
		} else {
			$.ajax('/ui/id/browse/1', {
				success: function(dataSet) {
					return dataSet;
				},
				error: function(){
					Index.createNotification('AJAX Failed.');
				},
   				type: 'GET'
			})
		}
	},

	reload: function() {
		$('.datatables-serverside-row-details').dataTable({
			"processing": true,
			"serverSide": true,
			'destroy': true,
			'ajax': url 
			//'data': TablesDataTablesSources.getDataSet(all)
		});
	},

	sourceJs: function (all) {
		if (all) {
			url = '/ui/id/browse/0';
		} else {
			url = '/ui/id/browse/1';
		}
		var table = $('.datatables-serverside-row-details').dataTable({
			"processing": true,
			"serverSide": true,
			'destroy': true,
			'ajax': url 
			//'data': TablesDataTablesSources.getDataSet(all)
		});
	},

	init: function () {
		this.sourceJs(false);

		$.extend( $.fn.dataTable.defaults, {
			fnDrawCallback: function( oSettings ) {
				$('.dataTables_wrapper select, .dataTables_wrapper input').removeClass('input-sm');
			}
		});
	}
}

