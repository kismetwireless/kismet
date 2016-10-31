;(function($, window, document, undefined) {

	function pushMenu (elem, options) {
		this.$body = $("body");
		this.$elem = $(elem);
		this.options = $.extend({}, this.config, options);
		this.$toggler = this.$body.find(this.options.button || '.open');
		this.initialize();
	}

	pushMenu.prototype.classes = {
		show : "pm_show",
		hide : "pm_hide",
		overlay : "pm_overlay",
		open : "pm_open"
	}

	pushMenu.prototype.initialize = function(){

		var _this = this;
		_this.initializeEvents();

		if(this.$body.find("."+this.classes.overlay).length < 1){
			var overlay = $("<div>").addClass(this.classes.overlay+" "+this.classes.hide);
			this.$body.append(overlay);
		}
	}

	pushMenu.prototype.initializeEvents = function(){

		var _this = this;

		this.$toggler.on('click', function(){
			_this.toggleMenu("show");
		});

		this.$body.on('click','.'+_this.classes.overlay, function(){
			_this.toggleMenu("hide");
		});
	}

	pushMenu.prototype.toggleMenu = function(status){
		var method = status == "show" ? "addClass" : "removeClass";
        // hack to remove initial hidden status - dragorn
        if (status === "show")
            this.$elem.removeClass("pm_initial");
		this.$elem[method](this.classes.open);
		this.toggleOverlay(status);
	}

	pushMenu.prototype.toggleOverlay = function(status){
		var _this = this;
		var overlay = _this.$body.find("."+_this.classes.overlay);
		if(status == "show"){
			overlay.addClass(_this.classes.show).removeClass(_this.classes.hide);
		}
		else{
			overlay.removeClass(this.classes.show);
			setTimeout(function(){
				overlay.addClass(_this.classes.hide);
			},500);
		}
	}

	$.fn.pushmenu = function(options){
		
		return this.each(function(){
			
			new pushMenu(this, options);
			
		});
		
	};
	
})(jQuery, window, document);
