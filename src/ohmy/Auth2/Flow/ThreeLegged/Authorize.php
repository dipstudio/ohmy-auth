<?php namespace ohmy\Auth2\Flow\ThreeLegged;

/*
 * Copyright (c) 2014, Yahoo! Inc. All rights reserved.
 * Copyrights licensed under the New BSD License.
 * See the accompanying LICENSE file for terms.
 */

use ohmy\Auth\Promise,
    ohmy\Components\Http;

class Authorize extends Promise {

    public $client;

    public function __construct($callback, Http $client=null) {
        parent::__construct($callback);
        $this->client = $client;
    }

    public function access($url, Array $options=array()) {
        $self = $this;
        $access = new Access(function($resolve, $reject) use($self, $url, $options) {
            $options += array(
                'grant_type'    => 'authorization_code',
                'client_id'     => $self->value['client_id'],
                'client_secret' => $self->value['client_secret'],
                'code'          => $self->value['code'],
                'redirect_uri'  => $self->value['redirect_uri']
            );
            $self->client->POST($url, $options, array())
            ->then(function($response) use($resolve) {
                $resolve($response->text());
            });

        }, $this->client);

        return $access->then(function($data) use($self) {

            $value = null;

            $json = json_decode($data, true);

            if ($json) {
                $value = array_merge($self->value, $json);
            } else {
                parse_str($data, $array);
                $value =  array_merge($self->value, $array);
            }
            return $value;
        });
    }
}
