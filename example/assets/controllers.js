var demoApp = angular.module('demoApp', [ ]);

demoApp.controller('VerifyCtrl', ['$scope', '$http', function ($scope, $http) {
      $scope.status = {
        color:   'text-muted',
        icon:    'glyphicon-minus',
        message: 'N/A'
      };

      $scope.verify   = function (passcode) {
        $http.post('verify', {
            'passcode': passcode
        } ).success(function ( ) {
            $scope.status = {
              color:   'text-success',
              icon:    'glyphicon-ok',
              message: 'Success'
            };
        } ).error(function ( ) {
            $scope.status = {
              color:   'text-danger',
              icon:    'glyphicon-remove',
              message: 'Failed'
            };
        } );
      };
} ] );
