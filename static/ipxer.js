const spinner = `
<div class="spinner">
  <div class="bounce1"></div>
  <div class="bounce2"></div>
  <div class="bounce3"></div>
</div>
`;

function isIPAddress(pathname) {
    if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(pathname)) {
        return (true)
    }
    return (false)
}

function newQuery(query) {
    $(".spinner").remove();
    $(".results").hide()
    $(".about").hide()
    $(".ipanswer").text("");
    if (isIPAddress(query)) {
        populateIPtable(query);
    } else if (query == "about") {
        $(".results").hide();
        $(".about").show();
    } else {
        populateRecords(query);
    }
}

function populateIPtable(query) {
    $(".ip-table").hide();
    $(spinner).insertBefore(".ip-table");
    $(spinner).insertBefore(".ptr-table");
    $(spinner).insertAfter(".reputation-table");
    $(".ip-results").show();
    $.getJSON('/api/ipv4/' + query, function(data) {
        if (data["error"]) {
            $(".ip-table").find("tbody").append('<td>' + data.error + '</td>');
        } else {
            $(".as").text(data["as"]);
            $(".asname").text(data["asname"]);
            $(".bgpprefix").text(data["bgpprefix"]);
            $(".registry").text(data["registry"]);
            $(".allocationdate").text(data["allocationdate"]);
            $(".country").text(data["country"]);
            $(".subdivision").text(data["subdivision"]);
            $(".city").text(data["city"]);
        }
    }).done(function() {
        $(".ip-table").show();
        $(".ip-table").prev(".spinner").remove();
        $(".ptr-table").prev(".spinner").remove();
        //$(".reputation-table").prev(".spinner").remove();
    });

    $.getJSON('/api/ptr/' + query, function(data) {
        if (data["error"]) {
            $(".ptr-table").find("tbody").append('<td colspan="3">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').html('<a href="/' + item.result + '">' + item.result + '</a>'),
                    $('<td>').text(item.ttl)
                );
                $(".ptr-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".ptr-table").show();
        $(".ptr-table").prev(".spinner").remove();
    });

    $.getJSON('/api/ipv4/otx/' + query, function(data) {
        if (data["error"]) {
            $(".reputation-table").find("tbody").append('<td colspan="5">' + data.error + '</td>');
        } else {
                var $tr = $('<tr>').append(
                    $('<td>').text('Alien Labs Open Threat Exchange'),
                    $('<td>').html('<a href="https://otx.alienvault.com/indicator/ip/' + query + '" target="_blank">' + data.otx_threat_score + ' out of 7</a>'),
                );
                $(".reputation-table").find("tbody").empty().append($tr)
        }
    }).done(function() {
        $(".reputation-table").show();
        //$(".reputation-table").next(".spinner").remove();
    });

    $.getJSON('/api/ipv4/xforce/' + query, function(data) {
        if (data["error"]) {
            $(".reputation-table").find("tbody").append('<td colspan="5">' + data.error + '</td>');
        } else {
                var $tr = $('<tr>').append(
                    $('<td>').text('IBM X-Force Exchange'),
                    $('<td>').html('<a href="https://exchange.xforce.ibmcloud.com/ip/' + query + '" target="_blank">' + data.xforce_threat_score + ' out of 10</a>'),
                );
                $(".reputation-table").find("tbody").append($tr)
        }
    }).done(function() {
        $(".reputation-table").show();
        $(".reputation-table").next(".spinner").remove();
    });

}

function populateRecords(query) {
    $(".dns-table").hide();
    $(".dns-results").show();
    $(spinner).insertBefore(".table");
    $.getJSON('/api/a/' + query, function(data) {
        if (data["error"]) {
            $(".a-table").find("tbody").append('<td colspan="3">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').html('<a href="/' + item.address + '">' + item.address + '</a>'),
                    $('<td>').text(item.ttl)
                );
                $(".a-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".a-table").show();
        $(".a-table").prev(".spinner").remove();
    });

    $.getJSON('/api/aaaa/' + query, function(data) {
        if (data["error"]) {
            $(".aaaa-table").find("tbody").append('<td colspan="3">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').text(item.address),
                    $('<td>').text(item.ttl)
                );
                $(".aaaa-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".aaaa-table").show();
        $(".aaaa-table").prev(".spinner").remove();
    });

    $.getJSON('/api/mx/' + query, function(data) {
        if (data["error"]) {
            $(".mx-table").find("tbody").append('<td colspan="4">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').html('<a href="/' + item.host + '">' + item.host + '</a>'),
                    $('<td>').text(item.preference),
                    $('<td>').text(item.ttl)
                );
                $(".mx-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".mx-table").show();
        $(".mx-table").prev(".spinner").remove();
    });

    $.getJSON('/api/ns/' + query, function(data) {
        if (data["error"]) {
            $(".ns-table").find("tbody").append('<td colspan="3">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').html('<a href="/' + item.result + '">' + item.result + '</a>'),
                    $('<td>').text(item.ttl)
                );
                $(".ns-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".ns-table").show();
        $(".ns-table").prev(".spinner").remove();
    });

    $.getJSON('/api/txt/' + query, function(data) {
        if (data["error"]) {
            $(".txt-table").find("tbody").append('<td colspan="3">' + data.error + '</td>');
        } else {
            let table = "";
            $.each(data.rows, function(i, item) {
                var $tr = $('<tr>').append(
                    $('<td>').text(item.type),
                    $('<td>').text(item.result),
                    $('<td>').text(item.ttl)
                );
                $(".txt-table").find("tbody").append($tr)
            });
        }
    }).done(function() {
        $(".txt-table").show();
        $(".txt-table").prev(".spinner").remove();
    });
}

$(".query").submit(function(event) {
    query = $(".queryValue").val();
    $(".ptr-table").find("tbody").empty();
    $(".dns-table").find("tbody").empty();
    history.pushState(null, null, $(".queryValue").val());
    if (query == '') {
        history.pushState(null, null, '/');
        $(".results").hide();
    } else {
        newQuery(query);
    }
    $(".queryValue").val("");
    $(".queryValue").attr("placeholder", window.location.pathname.substr(1));
    event.preventDefault();
});

if ("onhashchange" in window && window.location.pathname == '/about') {
    $(".results").hide();
    $(".about").show();
}

if ("onhashchange" in window && window.location.pathname != '/' && window.location.pathname != '/about') {
    query = window.location.pathname.substr(1);
    newQuery(query);
}

if (window.location.pathname == '/') {
    $(".about").hide();
    $(".results").hide();
    $(".queryValue").attr("placeholder", "example.com, 8.8.8.8");
} else {
    $(".queryValue").attr("placeholder", window.location.pathname.substr(1));
}

$(".queryValue").focus();
