<?php

class Cookie extends CookieCore
{

	public function __construct($name, $path = '', $expire = null, $shared_urls = null){
		$this->_content = array();
		$this->_expire = isset($expire) ? (int)($expire) : (time() + 1728000);
		$this->_name = md5(_PS_VERSION_.$name);
		$this->_path = '/';
		$this->_key = _COOKIE_KEY_;
		$this->_iv = _COOKIE_IV_;
		$this->_domain = $this->getDomain($shared_urls);
		$this->_allow_writing = true;
		if (Configuration::get('PS_CIPHER_ALGORITHM'))
			$this->_cipherTool = new Rijndael(_RIJNDAEL_KEY_, _RIJNDAEL_IV_);
		else
			$this->_cipherTool = new Blowfish($this->_key, $this->_iv);
		$this->update();
	}

	protected function _setcookie($cookie = null){
		if ($cookie){
			$content = $this->_cipherTool->encrypt($cookie);
			$time = $this->_expire;
		}else{
			$content = 0;
			$time = 1;
		}
		
		$path = (!defined('_PS_ADMIN_DIR_'))? null : $this->_path;
		if (PHP_VERSION_ID <= 50200) /* PHP version > 5.2.0 */
			return setcookie($this->_name, $content, $time, $path, $this->_domain, 0);
		else
			return setcookie($this->_name, $content, $time, $path, $this->_domain, 0, true);
	}

}

