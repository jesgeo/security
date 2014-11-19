<?php
	namespace Security;


	define('ROOT', "D:\Intranet\Intranet\Frontend\includes" . DIRECTORY_SEPARATOR);

	function __autoload($classname) {
		if (strpos($classname, __NAMESPACE__) === false)
			return;

	    $namespace = substr($classname, 0, strrpos($classname, '\\'));
	    $namespace = str_replace('\\', DIRECTORY_SEPARATOR, $classname);
	    $classPath = ROOT . $namespace . '.php';

	    $namespace = str_replace(__NAMESPACE__.'\\', "", $classname);
	    $wclass = ROOT . $namespace . '.php';


	    if(is_readable($classPath)) 
	        require_once $classPath;
	    if(is_readable($wclass)) 
	        require_once $wclass;
	}

	spl_autoload_register('Security\__autoload');



	use ErrorException;

	if($f = ZZFile::getCurrentFile()) {
		if(!$f->hasPerm(PrivilegedUser::getCurrentUser(), "full"))
			throw new ErrorException(" Access Denied :( ", 1);
			// header("Location: http://intranet/Intranet/Frontend/accessDenied.asp?username=".PrivilegedUser::getRemoteUserName());
	}
	



?>